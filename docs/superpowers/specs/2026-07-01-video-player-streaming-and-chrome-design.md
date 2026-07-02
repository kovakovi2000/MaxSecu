# Video player: streaming playback engine + YouTube-baseline chrome

**Date:** 2026-07-01
**Branch:** `feat/universal-video-ingest`
**Status:** Design approved; ready for implementation plan.

## Problem

Live GUI testing of the sandboxed video player surfaced that playback is
fundamentally broken, not merely unpolished:

- **Video freezes after a few frames while audio keeps playing.** The author
  preview (`preview_video`) decodes the *entire* clip up front and delivers all
  frames in one burst; the player caps its pending-frame queue at 96 and drops
  the overflow, while the audio is pre-scheduled on the WebAudio timeline and
  plays on regardless. Video starves; audio runs.
- **Play/Stop has no effect.** Same root: audio is pre-scheduled, so `pause()`
  only stops the video loop, never the audio.
- **"Can only check a video once" / seek is dead.** `player.seek()` clears the
  frame buffer expecting a re-decode, but preview has nothing to re-decode from,
  so the video disappears.
- **Timer stuck at `0:00`.** The time readout reports the last *drawn* frame's
  pts, which stops updating the instant video freezes.
- **A 59.5 s clip is stuck on "Loading… Decode worker pending".** Confirmed by
  probe: `Car crash call #skit #funny #comedy.mp4` is 59.5 s at 720×1280 ≈ 1,780
  I420 frames × 1.38 MB ≈ **2.4 GB** of decoded frames pushed into the WebView at
  once. It does not hang on a decoder bug — it drowns in its own data (the
  working test clip was only ~200 frames). The download path has the mirror
  defect: it decodes only the first window (`PLAY_WINDOW = 4` fragments) and
  never advances.

The common flaw: **decode-the-whole-clip-at-once does not scale**, and no
component drives decode from the play position.

## Decisions (from brainstorming)

- **Substrate: keep the confined pure-Rust decode sandbox unchanged (Option A).**
  Playback stays on the WebGL YUV canvas fed by the confined `media-worker`; we do
  NOT switch to a native `<video>` element. Reason: feeding decrypted,
  attacker-authored bytes to the browser's native C codec would re-introduce the
  exact RCE surface Phase 7 was built to eliminate. The choppiness is fixable
  engine bugs, not a limit of the sandbox. **No security-posture change; no
  re-review required.** ("Nothing sensitive to disk" is preserved — all decrypted
  frames/PCM remain RAM-only, as today.)
- **Sequencing: playback engine first (Stage 1), then chrome (Stage 2).**
- **Chrome via Media Chrome** (Mux's framework-agnostic web components), not
  hand-built. Bundled into `main.js` — no external loads, no CSP change.
- **Extras in scope:** keyboard shortcuts, auto-hide controls, click/double-click
  gestures. **Dropped:** playback-speed menu.
- **Out of scope (YAGNI):** PiP, captions, quality selector, adaptive bitrate.

## Stage 1 — Streaming playback engine

**Model: position-driven streaming windows with bounded RAM.** Playback drives
decode. The player keeps a small rolling buffer of frames *ahead* of the play
position; when the buffer runs low it requests the next window; frames behind the
position are discarded. WebView memory is bounded regardless of clip length, and
the same model serves both preview (staged CMAF) and download (server fetch).

### Two-tier memory model (the YouTube behavior, sized correctly)

The two representations of the video differ in size by ~1000×, so they are cached
at different layers:

- **Tier 1 — compressed source cache ("what's loaded", persists).** The
  encrypted/compressed fragments — a few hundred MB for a several-hundred-MB
  source. This is the grey "buffered" region: once a fragment is here, seeking to
  it needs **no re-download**, only a re-decode. **This already exists:**
  - Download path: `crate::fragment_cache::FragmentCache` — on-disk, encrypted
    (ciphertext only), byte-capped by the `ram_cache_cap_mb` setting;
    `feed_fragment` already serves cache hits with zero network.
  - Preview path: the whole staged CMAF plaintext is already held in the
    `UploadJobs` registry (RAM, `Zeroizing`), so every seek is a local re-decode.
  So "keep what's already played so we don't fetch it again" is satisfied at this
  layer today; the work is to *surface* it (buffered bar) and to make the frontend
  rely on it instead of hoarding decoded frames.

- **Tier 2 — decoded-frame rolling buffer ("what's on screen now", tiny).** I420
  frames are ~1.4 MB each (a 59 s 720p clip fully decoded ≈ 2.4 GB; a 10–20 min
  HD/4K clip would be tens–hundreds of GB — so it is **never** materialized).
  Only a small window near the playhead is held, bounded in **BYTES** (not frame
  count — a 4K frame is ~12 MB, a 1080p frame ~3 MB, so a fixed count would swing
  wildly), e.g. a ~128–256 MB ceiling. Frames far behind/ahead of the playhead are
  evicted; a seek-back **re-decodes from the Tier-1 cache** (fast, no network),
  exactly as YouTube re-decodes from its buffered segments rather than storing
  decoded pixels.

The decoded rolling buffer is the hard RAM cap; the compressed cache is the
"loaded" region. Neither grows with clip length: minutes-long 4K clips stream in
bounded memory.

### Components

1. **Pausable master clock.** Pause/resume uses `AudioContext.suspend()` /
   `resume()` so the audio *and* the clock the video syncs against freeze
   together. The video sync in `tick()` already reads `audioClock() -
   playbackStart`; suspending the context freezes `currentTime`, so held frames
   stay held and audio stops — real pause. Fixes "Play/Stop does nothing."

2. **Streaming window scheduler** (`core/player.ts`). Owns the play position and a
   target buffer horizon (e.g. ~2–3 s of frames ahead). When buffered-ahead drops
   below the low-water mark AND playback is advancing (not paused/seeking), it
   invokes an injected `requestWindow(fromPts | fromSeq)` callback (the component
   wires it to the backend). Frames far from the playhead are evicted so the
   decoded buffer stays under its **byte** ceiling (Tier 2 above) — replacing the
   fixed 96-*count* `pendingCapacity` drop that discarded needed frames. A
   seek-back re-requests the target window, which the backend serves from the
   Tier-1 cache with no network. Fixes the freeze, the "only first few frames,"
   and the 2.4 GB overload.

3. **Windowed preview backend.** Add `preview_window(job_id, start_seq, count)` in
   `commands/video.rs`, mirroring `play_window_command`: slice the staged
   `preview.cmaf` by the fragment index (as `build_preview_script` does, but for a
   bounded `[start_seq, start_seq+count)` range), decode confined, re-validate,
   emit the same frame/PCM/phase events. `preview_video` becomes the initial-window
   call (start 0); the scheduler requests subsequent windows via `preview_window`.
   The whole-clip `build_preview_script` path is retired.
   - The download path already has `play_window`/`video_seek`; the scheduler drives
     them the same way (request next window as playback advances), which it does
     NOT do today.

4. **Buffering indicator.** An honest `Buffering` state with "N s ready" (or a
   spinner) while a window decodes, replacing the frozen "Decode worker pending"
   badge. The badge is retired on the first real phase/frame (as today); the
   scheduler surfaces underruns as `Stalled` → `Buffering` → `Playing`.

5. **Position + duration tracking.** Total duration comes from the fragment index
   (per-fragment `pts_ms`; last fragment pts + its span ≈ total) — available in
   both `preview.index` and the download job's index, so the backend returns it to
   the UI (or the UI derives it from the index it already receives). The timer and
   scrubber read the *play position* from the clock, not the last-drawn frame.
   Fixes "0:00 / 0:18 stuck at 0:00" → live "0:23 / 0:59" and makes the scrubber a
   real seek surface (seek = set position, clear buffers, stop audio, request the
   window at the target seq/pts).

6. **No autoplay.** The player holds on the first decoded frame as a poster and
   starts only on user `play()` (the existing `reducedMotion` hold generalizes to
   an always-on "don't autostart" default). Removes the surprise autoplay.

### Data flow (both paths)

```
user Play ─▶ scheduler needs [pos, pos+horizon)
          ─▶ requestWindow(seq)  ─▶ backend decode window (confined)
                                     └▶ frame/PCM/phase events ─▶ player buffer
          ─▶ clock advances ─▶ tick() draws due frames, drops stale
          ─▶ buffered-ahead < low-water ─▶ requestWindow(next seq)  (repeat)
seek ─▶ clear buffers + stop audio + set pos ─▶ requestWindow(seq@target)
pause ─▶ AudioContext.suspend()   resume ─▶ AudioContext.resume()
```

Only decoded frames/PCM/phase DTOs cross the seam (unchanged). Decrypt +
decode stay in the TCB / confined worker (unchanged).

## Stage 2 — YouTube-baseline chrome (Media Chrome)

**Media Chrome web components** render the overlaid control bar and behaviors:
`<media-controller>`, `<media-play-button>`, `<media-time-range>` (scrubber),
`<media-time-display>`, `<media-volume-range>`, `<media-mute-button>`,
`<media-fullscreen-button>`, `<media-gesture-receiver>` (click/dblclick), plus
built-in `hotkeys` (Space/←/→/F/M) and `autohide`.

**The adapter.** Media Chrome coordinates with a "media element." Our player is a
WebGL canvas, not `<video>`, so we wrap the canvas + engine in a custom element
exposing the `HTMLMediaElement` slice Media Chrome reads/writes:
`currentTime` (get→position / set→seek), `duration`, `paused`, `play()`,
`pause()`, `volume`, `muted`, `buffered` (a `TimeRanges`-like shim that reports
the **Tier-1 cached fragments'** pts ranges — so `<media-time-range>` draws the
YouTube-style grey "loaded" bar and makes visible which seeks are instant/no-network),
and it dispatches the events Media Chrome listens for: `play`, `pause`,
`timeupdate`, `durationchange`, `volumechange`, `waiting`/`playing` (buffering),
`loadedmetadata`. Fullscreen targets the `<media-controller>` container (the
canvas scales to fill via CSS). The engine does the real work underneath.

**Security/CSP:** everything is bundled into `main.js` (`default-src 'self'`),
styles inline (`style-src 'unsafe-inline'` already allowed). No native `<video>`,
no external fetch, no CSP change. Media Chrome is added to `ui/package.json`.

## Error handling

- **Underrun / seek into un-decoded range:** suspend the clock, show `Buffering`,
  resume on the window's arrival.
- **Decode failure (worker error / cap exceeded):** the existing sanitized
  `PlayerPhase::Error` (fail-closed, no decode oracle) is preserved; controls
  settle to an error state.
- **Bad fragment:** the existing resilient-skip → `Gap` surfaces as a brief
  buffering blip (no player-core change).
- **Very long/large clips:** bounded by the rolling buffer + the existing
  per-window backend session caps.

## Testing

- **`core/player.ts`** — node:test units for the streaming scheduler: prefetch
  fires at the low-water mark, frames behind position are dropped, pause via
  suspend/resume freezes the clock, seek clears + requests the target window,
  position/duration reporting, no-autoplay default. Uses the existing injectable
  audio/clock/subscribe fakes.
- **`preview_window`** — slice-correctness unit test (mirrors `build_preview_script`
  bounds) + an e2e window over staged CMAF.
- **Media-element adapter** — units for the `HTMLMediaElement` surface
  (currentTime/duration/paused/play/pause + event emission) with fakes.
- **`a11y.test.ts`** — updated for the Media Chrome DOM (Media Chrome ships
  accessible controls; the lint's expected state strings move accordingly).
- **Manual GUI smoke (user)** — real smoothness, fullscreen, keyboard, gestures,
  and the previously-stuck 59 s clip now streaming.

## Non-goals / preserved invariants

- No native `<video>`; confined pure-Rust decode unchanged.
- Decrypt stays in the TCB; only frame/PCM/phase DTOs cross the seam.
- No plaintext to disk (RAM-only frames/PCM), as today.
- Fail-closed decode errors; no decode oracle.
