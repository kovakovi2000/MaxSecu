# Video Player Streaming Engine (Stage 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rework the sandboxed video player into a position-driven streaming engine so playback is smooth, pause/seek/timer work, and minutes-long HD/4K clips stream in bounded RAM — without touching the confined pure-Rust decode sandbox.

**Architecture:** Playback drives decode. `core/player.ts` keeps a small, **byte-bounded** rolling buffer of decoded frames near the play position; when it runs low it asks the component (via an injected `requestWindow(pts)` callback) to decode the next window; frames far behind/ahead of the playhead are evicted. Pause is a real `AudioContext.suspend()/resume()` so audio and the video's master clock freeze together. The backend gains a windowed **preview** path (mirroring the existing download `video_seek` window) and emits **duration** metadata for the scrubber. Seeking back re-decodes from the existing Tier-1 caches (on-disk ciphertext for download; staged CMAF in RAM for preview) — no re-download.

**Tech Stack:** TypeScript ES modules + custom elements (esbuild bundle, `node:test`); Rust Tauri v2 commands; existing confined `media-worker` decode (unchanged).

**Scope:** This is Stage 1 only (the engine). Stage 2 (Media Chrome chrome) is a separate follow-up plan written after Stage 1 is smoke-tested. Spec: `docs/superpowers/specs/2026-07-01-video-player-streaming-and-chrome-design.md`.

---

## File Structure

- `crates/client-app/ui/src/core/player.ts` — **the core rework**: pausable clock, byte-bounded buffer, position/duration tracking, no-autoplay, streaming scheduler, seek. (~one focused module; already exists.)
- `crates/client-app/ui/src/core/player.test.ts` — extend with streaming/scheduler/pause tests (existing harness).
- `crates/client-app/src/commands/video.rs` — add windowed preview (`preview_video` → window 0 + `preview_seek`), emit `VideoInfo` (duration). Reuse `play_window_command` for download.
- `crates/client-app/src/state.rs` — add `EVT_VIDEO_INFO` + `VideoInfo` DTO.
- `crates/client-app/ui/src/core/player.ts` (types) + `components/video-player.ts` — wire `requestWindow` to backend, consume duration, no-autoplay, seek, buffering label.
- `crates/client-app/ui/src/core/types.ts` — `VideoInfo` TS type.

---

## Task 1: Pausable master clock (AudioContext.suspend/resume)

**Files:**
- Modify: `crates/client-app/ui/src/core/player.ts`
- Test: `crates/client-app/ui/src/core/player.test.ts`

The `AudioContextLike` interface must gain `suspend()`/`resume()`, `pause()` must call `suspend()` and `play()` must call `resume()`, so pre-scheduled audio stops when paused (today it plays on).

- [ ] **Step 1: Add suspend/resume to the fake audio in the test and write a failing test**

In `player.test.ts`, extend `FakeAudio` (after the `createBufferSource` method, before the closing brace of the class):

```typescript
  suspended = 0;
  resumed = 0;
  async suspend(): Promise<void> {
    this.suspended++;
  }
  async resume(): Promise<void> {
    this.resumed++;
  }
```

Add this test at the end of the file:

```typescript
test("pause() suspends the audio context; play() resumes it", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => audio.currentTime,
  });
  player.play();
  assert.strictEqual(audio.resumed, 1, "play() resumes the context");
  player.pause();
  assert.strictEqual(audio.suspended, 1, "pause() suspends the context");
  player.play();
  assert.strictEqual(audio.resumed, 2, "play() resumes again");
  player.dispose();
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd crates/client-app/ui && npx tsx --test src/core/player.test.ts` (or `npm test`)
Expected: FAIL — `audio.suspend is not a function` / property `suspended` never incremented, and TS error that `suspend`/`resume` are not on `AudioContextLike`.

- [ ] **Step 3: Add suspend/resume to the interface and call them from play/pause**

In `player.ts`, extend `AudioContextLike` (add the two optional methods so the real WebAudio `AudioContext`, which has them, stays assignable):

```typescript
export interface AudioContextLike {
  readonly currentTime: number;
  readonly destination: unknown;
  createGain(): GainLike;
  createBuffer(channels: number, length: number, sampleRate: number): AudioBufferLike;
  createBufferSource(): AudioBufferSourceLike;
  // Pause/resume the whole audio clock so scheduled audio + the video master
  // clock freeze together (real pause). Optional so non-audio fakes can omit them.
  suspend?(): Promise<void>;
  resume?(): Promise<void>;
}
```

Change `play()` and `pause()`:

```typescript
  function play(): void {
    if (disposed) return;
    playing = true;
    started = true;
    void audio.resume?.();
    startLoop();
  }

  function pause(): void {
    playing = false;
    void audio.suspend?.();
    stopLoop();
  }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd crates/client-app/ui && npm test`
Expected: PASS (all existing tests still green).

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/core/player.ts crates/client-app/ui/src/core/player.test.ts
git commit -m "fix(player): pause() suspends the AudioContext so audio actually stops"
```

---

## Task 2: No autoplay by default

**Files:**
- Modify: `crates/client-app/ui/src/core/player.ts`
- Test: `crates/client-app/ui/src/core/player.test.ts`

Today the player autostarts on the first frame unless `reducedMotion`. Invert: never autostart; playback begins only on an explicit `play()`.

- [ ] **Step 1: Write the failing test**

```typescript
test("does not autostart on the first frame; play() is required", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const drawn: YuvFrame[] = [];
  let clock = 0;
  const player = createPlayer({
    audio,
    renderer: (f) => drawn.push(f),
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => clock,
  });
  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  assert.strictEqual(player.isPlaying(), false, "no autostart");
  player.tick();
  assert.strictEqual(drawn.length, 0, "nothing drawn until play()");
  player.play();
  player.tick();
  assert.strictEqual(drawn.length, 1, "draws after play()");
  player.dispose();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd crates/client-app/ui && npm test`
Expected: FAIL — `isPlaying()` is `true` after the first frame (autostart fires).

- [ ] **Step 3: Remove the first-frame autostart**

In `player.ts` `onFrame`, delete the autostart block:

```typescript
    pushRing(frame);
    // (removed) no autostart — playback begins only on an explicit play()
```

(Delete the `if (!started) { started = true; if (!reducedMotion) play(); }` lines. `reducedMotion` is now unused for autostart; keep the option in the interface for the component's "press play" poster hint but stop reading it here — remove the `const reducedMotion = opts.reducedMotion;` line and its use.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd crates/client-app/ui && npm test`
Expected: PASS. (If an older test asserted autostart, update it to call `player.play()` first.)

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/core/player.ts crates/client-app/ui/src/core/player.test.ts
git commit -m "feat(player): no autoplay — playback starts only on explicit play()"
```

---

## Task 3: Position + duration tracking, and correct playback origin

**Files:**
- Modify: `crates/client-app/ui/src/core/player.ts`
- Test: `crates/client-app/ui/src/core/player.test.ts`

Expose the live play **position** (from the clock, not the last drawn frame) and a settable **duration**, so the timer shows `0:23 / 0:59` instead of sticking at `0:00`.

**Also fix the playback origin under no-autoplay (introduced by Task 2).** Today the origin (`playbackStart`) is captured on the first *frame/audio arrival* via `ensurePlaybackStart()`. With no autoplay, a user who buffers a poster and waits before pressing Play would get a stale origin — the whole buffer would read as "due" and skip. The origin must be captured at **`play()`**, and the `AudioContext` must start **suspended** so the clock is frozen and any pre-play audio chunks stay silent until Play.

- [ ] **Step 1: Write the failing tests**

Add both tests at the end of `player.test.ts`:

```typescript
test("positionMs tracks the clock from play(); duration is settable", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  let clock = 0;
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => clock,
  });
  player.setDuration(59000);
  assert.strictEqual(player.durationMs(), 59000);
  player.play(); // clock=0 -> playbackStart captured at 0
  clock = 2.5; // 2.5 s elapsed
  assert.strictEqual(player.positionMs(), 2500, "position follows the clock");
  player.dispose();
});

test("origin is captured at play(), not at frame arrival (wait-then-play does not skip)", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  let clock = 0;
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => clock,
  });
  bus.emit(EVT_VIDEO_FRAME, frameDto(0)); // buffered as a poster; origin NOT set yet
  assert.strictEqual(player.positionMs(), 0, "no origin before play()");
  clock = 5; // the user stares at the poster for 5 s
  player.play(); // origin captured NOW (at clock=5)
  assert.strictEqual(player.positionMs(), 0, "elapsed is 0 at play, not 5000 — no skip");
  player.dispose();
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd crates/client-app/ui && npm test`
Expected: FAIL — `player.setDuration`/`positionMs`/`durationMs` not functions; and (once those exist) the wait-then-play test fails because the origin is still captured on frame arrival.

- [ ] **Step 3: Implement position/duration + the origin fix**

In `player.ts`:

(a) Add duration state near the other `let` declarations:

```typescript
  let durationMs = Math.max(0, opts.durationMs ?? 0);
```

(b) **Suspend the context at init** — add this right after `gain.gain.value = volume;` in `createPlayer`:

```typescript
  // No autoplay: start suspended so the audio clock is frozen and any pre-play audio
  // chunks stay silent until the user presses Play (which resume()s the context).
  void audio.suspend?.();
```

(c) **Capture the origin at play()** — in `play()`, after `void audio.resume?.();`, add:

```typescript
    if (playbackStart === null) playbackStart = audioClock();
```

(d) **Stop capturing the origin on arrival** — remove the `ensurePlaybackStart();` call from the top of `onFrame` AND from the top of `onAudio`, and delete the now-unused `ensurePlaybackStart` function. (The `tick()` fallback `if (playbackStart === null) playbackStart = audioClock();` remains, so after a `seek()` — which sets `playbackStart = null` while still playing — the next tick re-captures the origin.)

(e) Add the `positionMs` helper (near `tick`):

```typescript
  // Current play position in ms: elapsed since playbackStart, or 0 before it is set.
  function positionMs(): number {
    if (playbackStart === null) return 0;
    return Math.max(0, Math.round((audioClock() - playbackStart) * 1000));
  }
```

(f) Add to `PlayerOptions`:

```typescript
  // Total clip duration in ms (from the fragment index). May be set later via setDuration().
  durationMs?: number;
```

(g) Add to the `Player` interface:

```typescript
  positionMs(): number;
  durationMs(): number;
  setDuration(ms: number): void;
```

(h) Add to the returned object:

```typescript
    positionMs,
    durationMs: () => durationMs,
    setDuration: (ms: number) => {
      durationMs = Math.max(0, ms);
    },
```

- [ ] **Step 4: Update the Task-1 test for the init-suspend, then run**

`createPlayer` now calls `audio.suspend?.()` once at construction, so the Task-1 test `"pause() suspends the audio context; play() resumes it"` (which asserts absolute counts of `1`) must become delta-based. Rewrite its assertions to capture baselines after construction:

```typescript
  const s0 = audio.suspended, r0 = audio.resumed;
  player.play();
  assert.strictEqual(audio.resumed, r0 + 1, "play() resumes the context");
  player.pause();
  assert.strictEqual(audio.suspended, s0 + 1, "pause() suspends the context");
  player.play();
  assert.strictEqual(audio.resumed, r0 + 2, "play() resumes again");
```

Then check the whole suite. Some existing A/V-sync tests emit frames/audio and `tick()` — they call `player.play()` before relying on timing, so the origin is now captured at that `play()`. If any pre-existing test emitted frames/audio and asserted drawing/scheduling **without** calling `play()` first (relying on origin-at-arrival), fix it minimally by calling `player.play()` at the right point (do NOT weaken assertions). Report exactly which tests you touched.

Run: `cd crates/client-app/ui && npm test && npm run typecheck`
Expected: PASS + clean typecheck.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/core/player.ts crates/client-app/ui/src/core/player.test.ts
git commit -m "feat(player): live positionMs()/duration + capture the clock origin at play() (no-autoplay-safe)"
```

---

## Task 4: Byte-bounded decoded buffer with position-relative eviction

**Files:**
- Modify: `crates/client-app/ui/src/core/player.ts`
- Test: `crates/client-app/ui/src/core/player.test.ts`

Replace the fixed 96-**count** `pendingCapacity` (which dropped needed early frames on a burst) with a **byte** ceiling and position-relative eviction: keep frames from `position - KEEP_BEHIND_MS` up to the frontier, and if total decoded bytes exceed the cap, drop the oldest.

- [ ] **Step 1: Write the failing test**

```typescript
test("evicts decoded frames by BYTE budget, not a fixed count", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  let clock = 0;
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => clock,
    // Each 2x2 frame is y(4)+u(1)+v(1) = 6 bytes; cap at 18 bytes => at most 3 frames buffered.
    maxBufferBytes: 18,
  });
  player.play();
  for (let i = 0; i < 10; i++) bus.emit(EVT_VIDEO_FRAME, frameDto(i * 1000));
  // Buffer is byte-bounded: far more than 3 arrived, but only ~3 frames' worth is retained.
  assert.ok(player.bufferedBytes() <= 18, `buffered ${player.bufferedBytes()} <= 18`);
  player.dispose();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd crates/client-app/ui && npm test`
Expected: FAIL — `maxBufferBytes` option / `bufferedBytes()` not present; buffer bounded by count instead.

- [ ] **Step 3: Implement byte-bounded eviction**

In `player.ts`:

Add option to `PlayerOptions` (and remove the now-obsolete `pendingCapacity` doc/option):

```typescript
  // Byte ceiling on the decoded-frame buffer (default 192 MiB). Decoded I420 frames are
  // ~1.4 MB each, so this bounds WebView RAM regardless of clip length. Over the cap the
  // OLDEST frame is dropped (counted). A byte cap (not a frame count) is correct because a
  // 4K frame is ~12 MB and a 1080p frame ~3 MB.
  maxBufferBytes?: number;
```

Add state + a frame-size helper:

```typescript
  const maxBufferBytes = Math.max(1, opts.maxBufferBytes ?? 192 * 1024 * 1024);
  // Retain a little played history for tiny back-scrubs before re-decoding from Tier-1.
  const KEEP_BEHIND_MS = 1500;
  let bufferedBytes = 0;

  function frameBytes(f: YuvFrame): number {
    return f.y.length + f.u.length + f.v.length;
  }
```

Rewrite the tail of `onFrame` (replace the `while (pending.length > pendingCapacity) {...}` block):

```typescript
    pending.push(frame);
    bufferedBytes += frameBytes(frame);
    evictBuffer();
    pushRing(frame);
```

Add the eviction function (near `tick`):

```typescript
  // Keep the decoded buffer bounded: first drop frames well behind the playhead
  // (a back-scrub re-decodes from the Tier-1 cache), then enforce the byte ceiling
  // by dropping the oldest. Always keep at least one frame so tick() has something.
  function evictBuffer(): void {
    const floor = positionMs() - KEEP_BEHIND_MS;
    while (pending.length > 1 && pending[0].pts_ms < floor) {
      bufferedBytes -= frameBytes(pending.shift() as YuvFrame);
      droppedCount++;
    }
    while (pending.length > 1 && bufferedBytes > maxBufferBytes) {
      bufferedBytes -= frameBytes(pending.shift() as YuvFrame);
      droppedCount++;
    }
  }
```

In `tick()`, when a frame is shifted for drawing, decrement `bufferedBytes`:

```typescript
      if (toDraw !== null) { droppedCount++; bufferedBytes -= frameBytes(toDraw); }
      toDraw = pending.shift() as YuvFrame;
```

and after the loop, before `drawFrame(toDraw)`:

```typescript
    if (toDraw) {
      bufferedBytes -= frameBytes(toDraw);
      drawnCount++;
      drawFrame(toDraw);
    }
```

In `seek()` and `dispose()`, reset `bufferedBytes = 0;` where `pending.length = 0;` is set. Add `bufferedBytes: () => bufferedBytes` to the returned object and `bufferedBytes(): number;` to the `Player` interface.

- [ ] **Step 4: Run to verify it passes**

Run: `cd crates/client-app/ui && npm test`
Expected: PASS. Update/remove the old "bounds the pending queue" count-cap tests (lines ~422–470 of `player.test.ts`) — rewrite them to assert byte-bounded behavior or delete if redundant with the new test.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/core/player.ts crates/client-app/ui/src/core/player.test.ts
git commit -m "feat(player): byte-bounded decoded buffer + position-relative eviction (fixes burst overflow)"
```

---

## Task 5: Streaming window scheduler (prefetch on low-water)

**Files:**
- Modify: `crates/client-app/ui/src/core/player.ts`
- Test: `crates/client-app/ui/src/core/player.test.ts`

When playing and the buffered frontier is within `LOW_WATER_MS` of the play position, ask the component to decode the next window via an injected `requestWindow(fromPtsMs)` — once per outstanding window (guarded until new frames extend the frontier).

- [ ] **Step 1: Write the failing test**

```typescript
test("requests the next window when the buffered frontier runs low", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  let clock = 0;
  const requested: number[] = [];
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => clock,
    bufferAheadMs: 3000,
    lowWaterMs: 1500,
    requestWindow: (pts) => requested.push(pts),
  });
  player.play();
  // Frontier at 1000 ms, position 0 => ahead = 1000 < lowWater(1500) => request once.
  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  bus.emit(EVT_VIDEO_FRAME, frameDto(1000));
  player.tick();
  assert.deepStrictEqual(requested, [1000], "requested next window at the frontier");
  // No duplicate request while the same window is outstanding.
  player.tick();
  assert.deepStrictEqual(requested, [1000], "no duplicate request");
  // New frames extend the frontier past position+lowWater => guard clears, no new request yet.
  bus.emit(EVT_VIDEO_FRAME, frameDto(2000));
  bus.emit(EVT_VIDEO_FRAME, frameDto(3000));
  player.tick();
  assert.deepStrictEqual(requested, [1000], "frontier now ahead; still one request");
  player.dispose();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd crates/client-app/ui && npm test`
Expected: FAIL — `requestWindow`/`bufferAheadMs`/`lowWaterMs` options unused; `requested` stays empty.

- [ ] **Step 3: Implement the scheduler**

Add options to `PlayerOptions`:

```typescript
  // Streaming: target frames buffered AHEAD of the playhead (ms) and the low-water mark
  // at which the next window is requested. requestWindow(fromPtsMs) asks the component to
  // decode the window covering fromPtsMs (it maps pts -> fragment seq and calls the backend).
  bufferAheadMs?: number;
  lowWaterMs?: number;
  requestWindow?: (fromPtsMs: number) => void;
```

Add state:

```typescript
  const bufferAheadMs = opts.bufferAheadMs ?? 3000;
  const lowWaterMs = opts.lowWaterMs ?? 1500;
  const requestWindow = opts.requestWindow;
  let frontierMs = 0;        // max pts received so far
  let windowOutstanding = false; // a requestWindow is in flight (until the frontier advances)
```

In `onFrame`, after pushing, update the frontier + clear the guard when it advances:

```typescript
    if (frame.pts_ms > frontierMs) {
      frontierMs = frame.pts_ms;
      windowOutstanding = false; // new frames arrived; allow the next request
    }
```

Add the prefetch check, called from `tick()` (add a call to `maybePrefetch()` at the top of `tick()` after the `playing` guard):

```typescript
  function maybePrefetch(): void {
    if (!playing || windowOutstanding || !requestWindow) return;
    // Ahead = how far the buffered frontier leads the playhead.
    const ahead = frontierMs - positionMs();
    if (ahead < lowWaterMs && frontierMs < durationMs) {
      windowOutstanding = true;
      requestWindow(frontierMs); // decode the window starting after the frontier
    }
  }
```

Note: `bufferAheadMs` documents the target horizon; the low-water mark is the trigger. If `durationMs` is 0 (unknown), the `frontierMs < durationMs` guard is skipped by initializing `durationMs` handling — change the guard to `(durationMs === 0 || frontierMs < durationMs)`.

Reset `frontierMs = 0; windowOutstanding = false;` in `seek()` and `dispose()`.

- [ ] **Step 4: Run to verify it passes**

Run: `cd crates/client-app/ui && npm test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/core/player.ts crates/client-app/ui/src/core/player.test.ts
git commit -m "feat(player): streaming scheduler requests the next window at the low-water mark"
```

---

## Task 6: Seek re-requests the window at the target

**Files:**
- Modify: `crates/client-app/ui/src/core/player.ts`
- Test: `crates/client-app/ui/src/core/player.test.ts`

`seek(pts)` must clear the buffer, stop in-flight audio, reset the frontier to the target, and request the window at the target (so it plays from there instead of vanishing).

- [ ] **Step 1: Write the failing test**

```typescript
test("seek clears the buffer and requests the window at the target", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  let clock = 0;
  const requested: number[] = [];
  const seeked: number[] = [];
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => clock,
    requestWindow: (pts) => requested.push(pts),
    onSeek: (pts) => seeked.push(pts),
  });
  player.play();
  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  bus.emit(EVT_VIDEO_FRAME, frameDto(1000));
  player.seek(30000);
  assert.strictEqual(player.bufferedBytes(), 0, "buffer cleared on seek");
  assert.deepStrictEqual(seeked, [30000], "onSeek notified with the target");
  assert.deepStrictEqual(requested, [30000], "requested the window at the seek target");
  player.dispose();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd crates/client-app/ui && npm test`
Expected: FAIL — `seek()` clears but does not call `requestWindow`.

- [ ] **Step 3: Implement seek re-request**

Rewrite `seek()`:

```typescript
  function seek(pts_ms: number): void {
    pending.length = 0;
    ring.length = 0;
    bufferedBytes = 0;
    nextAudioTime = 0;
    playbackStart = null;
    frontierMs = pts_ms;      // the new window begins at the target
    windowOutstanding = true; // we are about to request it; guard until frames arrive
    stopAllSources();
    opts.onSeek?.(pts_ms);
    requestWindow?.(pts_ms);
  }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd crates/client-app/ui && npm test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/core/player.ts crates/client-app/ui/src/core/player.test.ts
git commit -m "feat(player): seek clears the buffer and requests the target window (re-watchable)"
```

---

## Task 7: Backend — windowed preview (`preview_video` window 0 + `preview_seek`)

**Files:**
- Modify: `crates/client-app/src/commands/video.rs`
- Modify: `crates/client-app/src/main.rs` (register `preview_seek`)
- Test: `crates/client-app/src/commands/video.rs` (unit test for the window slice)

`preview_video` currently decodes ALL fragments (the 2.4 GB overload). Make it decode only the first window; add `preview_seek(job_id, pts_ms)` to decode the window at any pts, mirroring the download `video_seek`/`play_window` shape.

- [ ] **Step 1: Write a failing unit test for the windowed preview slice**

In `video.rs` `#[cfg(test)] mod tests`, add (uses the existing `build_video`/`open_video_job_core` helpers pattern; adapt to the preview index which is a `Vec<FragmentEntry>`):

```rust
    #[test]
    fn preview_window_slice_covers_only_the_requested_fragments() {
        // A 5-fragment index over a cmaf tiled in VIDEO_CHUNK_SIZE units.
        let cs = crate::upload::VIDEO_CHUNK_SIZE as usize;
        let index: Vec<FragmentEntry> = (0..5)
            .map(|k| FragmentEntry { seq: k, pts_ms: k as u64 * 1000, chunk_start: k as u64, chunk_len: 1 })
            .collect();
        let cmaf = vec![7u8; 5 * cs];
        // Window [1,3) -> fragments seq 1,2 -> Open + 2 Fragments + Close.
        let guard = build_preview_window_script(&cmaf, &index, 1, 2).expect("script");
        let frags: Vec<u32> = guard.0.iter().filter_map(|m| match m {
            ClientMsg::Fragment { seq, .. } => Some(*seq),
            _ => None,
        }).collect();
        assert_eq!(frags, vec![1, 2], "only the requested window's fragments");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd crates/client-app && $env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app preview_window_slice -- --nocapture`
Expected: FAIL — `build_preview_window_script` does not exist.

- [ ] **Step 3: Add the windowed slice + `preview_seek`, refactor `preview_video`**

In `video.rs`, generalize `build_preview_script` to a bounded range and keep a whole-clip caller for nothing (remove the whole-clip use). Add:

```rust
/// Slice fragments `[start_seq, start_seq+count)` of the staged canonical `cmaf` into a
/// confined-decode script `Open -> Fragment* -> Close`. The bounded form of the old
/// whole-clip `build_preview_script` — so preview STREAMS a window instead of decoding the
/// entire clip (a 59 s clip is ~2.4 GB of frames). Fail-closed on an out-of-range slice.
fn build_preview_window_script(
    cmaf: &[u8],
    index: &[FragmentEntry],
    start_seq: u32,
    count: u32,
) -> Result<ScriptGuard, UiError> {
    if index.is_empty() { return Err(player_err()); }
    let cs = crate::upload::VIDEO_CHUNK_SIZE as usize;
    let n = index.len() as u32;
    if start_seq >= n { return Err(player_err()); }
    let end = start_seq.saturating_add(count).min(n);
    let mut script = ScriptGuard(Vec::with_capacity((end - start_seq) as usize + 2));
    script.0.push(ClientMsg::Open { bounds: VideoBounds::default() });
    for e in index.iter().filter(|e| e.seq >= start_seq && e.seq < end) {
        let start = (e.chunk_start as usize).checked_mul(cs).ok_or_else(player_err)?;
        let len = (e.chunk_len as usize).checked_mul(cs).ok_or_else(player_err)?;
        let end_b = start.checked_add(len).ok_or_else(player_err)?;
        let slice = cmaf.get(start..end_b).ok_or_else(player_err)?;
        script.0.push(ClientMsg::Fragment { seq: e.seq, bytes: slice.to_vec() });
    }
    script.0.push(ClientMsg::Close);
    Ok(script)
}
```

Refactor `preview_video_inner` to decode window 0 only (use `PLAY_WINDOW` and `build_preview_window_script(&preview.cmaf, &preview.index, 0, PLAY_WINDOW)` instead of `build_preview_script`), compute `window_start_pts` from `preview.index[0]`, and emit `VideoInfo` (Task 8). Add a `preview_seek` command:

```rust
/// `preview_seek` — decode the preview window covering `pts_ms` (author-side, staged cmaf,
/// no server, no decrypt). Mirrors `video_seek` for the download path. Sanitized errors.
#[tauri::command]
pub async fn preview_seek(
    job_id: String,
    pts_ms: u64,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    jobs: State<'_, crate::jobs::UploadJobs>,
) -> Result<(), UiError> {
    let emit = |p: PlayerPhase| { let _ = app.emit(EVT_PLAYER, p); };
    let on_frame = |f: I420FrameDto| { let _ = app.emit(EVT_VIDEO_FRAME, f); };
    let on_audio = |a: PcmDto| { let _ = app.emit(EVT_VIDEO_AUDIO, a); };
    let out = preview_window_inner(&job_id, pts_ms, &dir, &jobs, &emit, &on_frame, &on_audio).await;
    if let Err(e) = &out { emit(PlayerPhase::Error { code: e.code.clone() }); }
    out
}
```

Factor a `preview_window_inner(job_id, pts_ms, ...)` that: locks `UploadJobs`, gets `staged.preview`, maps `pts_ms` -> `start_seq` via `fragment_for_time(&preview.index, pts_ms).unwrap_or(0)`, builds `build_preview_window_script(&preview.cmaf, &preview.index, start_seq, PLAY_WINDOW)`, clones the index + window_start_pts, releases the lock, then `decode_and_emit(...)`. Make `preview_video_inner` delegate to `preview_window_inner(job_id, 0, ...)` after emitting `VideoInfo`.

- [ ] **Step 4: Register `preview_seek` and run tests**

In `main.rs` `invoke_handler`, add `maxsecu_client_app::commands::video::preview_seek,`.

Run: `cd crates/client-app && $env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app preview_window_slice`
Expected: PASS. Also `cargo build -p maxsecu-client-app` compiles.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/commands/video.rs crates/client-app/src/main.rs
git commit -m "feat(video): windowed preview (preview_video window 0 + preview_seek) — no whole-clip decode"
```

---

## Task 8: Backend — emit `VideoInfo` (duration) at open

**Files:**
- Modify: `crates/client-app/src/state.rs`
- Modify: `crates/client-app/src/commands/video.rs`
- Modify: `crates/client-app/ui/src/core/types.ts`
- Test: `crates/client-app/src/state.rs` (serialization test)

Emit a `VideoInfo { duration_ms, fragment_count }` event at `open_video`/`preview_video` so the scrubber has a max and the timer a denominator.

- [ ] **Step 1: Write the failing serialization test**

In `state.rs` add:

```rust
#[cfg(test)]
mod video_info_tests {
    use super::*;
    #[test]
    fn video_info_serializes() {
        let s = serde_json::to_string(&VideoInfo { duration_ms: 59000, fragment_count: 5 }).unwrap();
        assert!(s.contains("\"duration_ms\":59000"));
        assert!(s.contains("\"fragment_count\":5"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd crates/client-app && $env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app video_info_serializes`
Expected: FAIL — `VideoInfo` undefined.

- [ ] **Step 3: Define `VideoInfo` + `EVT_VIDEO_INFO` and emit it**

In `state.rs`:

```rust
/// One-shot per-open metadata for the player UI (scrubber max + timer denominator).
pub const EVT_VIDEO_INFO: &str = "maxsecu://video-info";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VideoInfo {
    pub duration_ms: u64,
    pub fragment_count: u32,
}
```

Add a duration helper in `video.rs` (approximate total from the index: last fragment start + the last inter-fragment gap):

```rust
/// Approximate clip duration (ms) from the fragment index: the last fragment's start pts
/// plus one inter-fragment gap (fragments are ~uniform). Zero for an empty index.
fn duration_ms_from_index(index: &[FragmentEntry]) -> u64 {
    match (index.last(), index.len()) {
        (Some(last), n) if n >= 2 => {
            let gap = last.pts_ms.saturating_sub(index[n - 2].pts_ms);
            last.pts_ms.saturating_add(gap)
        }
        (Some(last), _) => last.pts_ms.saturating_add(1000),
        (None, _) => 0,
    }
}
```

Emit in `open_video_inner` (after `index` is known, before the first `play_window_command`) and in `preview_video_inner` (before decoding window 0):

```rust
    let _ = app_or_handle.emit(crate::state::EVT_VIDEO_INFO, crate::state::VideoInfo {
        duration_ms: duration_ms_from_index(&index),
        fragment_count: index.len() as u32,
    });
```

(For `open_video_inner`, thread the `app`/emit closure through as the other emits are; the command already has `app: tauri::AppHandle`. Add an `on_info` emit alongside `emit`/`on_frame`/`on_audio` in `open_video`/`preview_video` and pass it down.)

- [ ] **Step 4: Run tests**

Run: `cd crates/client-app && $env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo test -p maxsecu-client-app video_info_serializes` and `cargo build -p maxsecu-client-app`
Expected: PASS + compiles.

Add the TS type in `crates/client-app/ui/src/core/types.ts`:

```typescript
export interface VideoInfo { duration_ms: number; fragment_count: number }
```

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/src/state.rs crates/client-app/src/commands/video.rs crates/client-app/ui/src/core/types.ts
git commit -m "feat(video): emit VideoInfo(duration_ms, fragment_count) at open for the scrubber/timer"
```

---

## Task 9: Wire `video-player.ts` to the streaming engine

**Files:**
- Modify: `crates/client-app/ui/src/components/video-player.ts`
- Test: manual (Tauri/WebView2 + confined worker; not node-testable) + existing e2e in Task 10.

Wire `requestWindow` to the backend (`preview_seek` for preview, `video_seek` for download), consume `VideoInfo` for duration, honor no-autoplay (poster + Play), and drive the timer from `positionMs()`.

- [ ] **Step 1: Subscribe to `VideoInfo` and set duration**

In `connectedCallback`, alongside the `EVT_VIDEO_FRAME` subscription, add:

```typescript
    void on<VideoInfo>("maxsecu://video-info", (info) => {
      this.player?.setDuration(info.duration_ms);
      this.durationMs = info.duration_ms;
    }).then((un) => { if (this.disposed) un(); else this.uninfo = un; });
```

(Add `private uninfo: (() => void) | null = null;` and `private durationMs = 0;`, import `VideoInfo` from `../core/types.ts`, and call `this.uninfo?.()` in `disconnectedCallback`.)

- [ ] **Step 2: Pass `requestWindow` into `createPlayer`**

In the `createPlayer({...})` call, add:

```typescript
      requestWindow: (pts) => {
        if (this.previewJob) {
          void serial(() => call<void>("preview_seek", { jobId: this.previewJob, ptsMs: Math.round(pts) })).catch(() => {});
        } else {
          void serial(() => call<void>("video_seek", { fileId: this.reqId, ptsMs: Math.round(pts) })).catch(() => {});
        }
      },
```

- [ ] **Step 3: No-autoplay poster + timer from position**

Remove the reduced-motion autostart special-case text; instead always start paused with a "Press Play" status. In `refreshScrubber`, drive the scrubber/time from the player position + duration:

```typescript
  private refreshScrubber() {
    const scrub = this.querySelector("#vp-scrub") as HTMLInputElement | null;
    if (!scrub || !this.player) return;
    const pos = this.player.positionMs();
    const dur = this.player.durationMs() || this.durationMs;
    scrub.max = String(dur);
    if (!this.dragging) {
      scrub.value = String(pos);
      scrub.setAttribute("aria-valuenow", String(pos));
    }
    this.updateTime(pos, dur);
  }
```

The scrub `change` handler already calls `this.player?.seek(pts)`; since the player's `seek` now calls `requestWindow` itself, remove the separate `video_seek` call in the component's scrub handler (avoid a double request) — the engine owns it now.

- [ ] **Step 4: Build the UI and the exe**

Run:
```bash
cd crates/client-app/ui && npm run typecheck && npm run build && npm test
cd ../.. && $env:Path="$env:USERPROFILE\.cargo\bin;$env:Path"; cargo build --release -p maxsecu-client-app
```
Expected: typecheck + tests pass; exe builds.

- [ ] **Step 5: Commit**

```bash
git add crates/client-app/ui/src/components/video-player.ts
git commit -m "feat(video-player): drive streaming windows + duration + no-autoplay from the engine"
```

---

## Task 10: Stage the build and manual GUI smoke

**Files:**
- No code; staging + manual verification.

- [ ] **Step 1: Stage the rebuilt exe into both dist dirs**

Confirm the client is closed, then:
```bash
cd D:/scrs/programs/MaxSecu
cp target/release/maxsecu-client-app.exe dist/MaxSecuClient-root/maxsecu-client-app.exe
cp target/release/maxsecu-client-app.exe dist/MaxSecuClient-bob/maxsecu-client-app.exe
```

- [ ] **Step 2: Manual smoke (user-driven — WebView2 can't be automated)**

Verify, on `D:\Images\00168.mp4` (short) and `D:\Images\Car crash call #skit #funny #comedy.mp4` (59 s):
- Preview does NOT autoplay; Play starts it.
- Video plays smoothly start-to-finish (no freeze-with-audio); Pause stops BOTH audio and video; Play resumes.
- The timer advances (`0:23 / 0:59`), not stuck at `0:00`.
- The scrubber seeks; seeking back replays that part (re-watchable); the 59 s clip streams without hanging on "Loading".
- Windows advance automatically as playback proceeds (no stop after the first few seconds).

- [ ] **Step 3: Update the a11y lint if the status strings changed**

If `refreshScrubber`/status text changed the strings `a11y.test.ts` greps for, update `crates/client-app/ui/src/a11y.test.ts` accordingly and run `npm run test:a11y`.

- [ ] **Step 4: Commit any smoke-driven fixes**

```bash
git add -A
git commit -m "fix(video-player): live-smoke fixes for streaming playback"
```

---

## Self-review notes

- **Spec coverage:** pausable clock (T1), no-autoplay (T2), position/duration (T3, T8), byte-bounded buffer (T4), streaming scheduler (T5), seek/re-watch via Tier-1 (T6, backend reuse of caches unchanged), windowed preview (T7), duration metadata (T8), wiring + buffering feedback (T9), smoke (T10). Tier-1 caches (FragmentCache / staged CMAF) are unchanged and reused — no task needed.
- **Deferred to Stage 2 plan:** Media Chrome chrome, fullscreen, keyboard, auto-hide, gestures, the buffered "grey bar" surfacing. This plan makes playback correct and smooth; Stage 2 skins it.
- **Type consistency:** `positionMs()`, `durationMs()`, `setDuration()`, `bufferedBytes()`, `requestWindow`, `maxBufferBytes`, `bufferAheadMs`, `lowWaterMs` are defined in T1–T6 and consumed in T9; `VideoInfo`/`EVT_VIDEO_INFO`/`preview_seek`/`build_preview_window_script`/`duration_ms_from_index` in T7–T8.
