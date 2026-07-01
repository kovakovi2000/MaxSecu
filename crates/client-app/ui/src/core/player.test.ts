import { test } from "node:test";
import assert from "node:assert";
import {
  createPlayer,
  EVT_VIDEO_FRAME,
  type AudioContextLike,
  type GainLike,
  type AudioBufferLike,
  type AudioBufferSourceLike,
  EVT_VIDEO_AUDIO,
  type I420FrameDto,
  type PcmDto,
  type YuvFrame,
} from "./player.ts";

// ---- fakes (node has no WebAudio/WebGL/Tauri) ----------------------------

// A fake GainNode whose .gain.value the player drives for volume.
function fakeGain(): GainLike {
  return { gain: { value: 1 }, connect() {} };
}

// A fake buffer source that records its start/stop lifecycle.
interface FakeSource extends AudioBufferSourceLike {
  started: boolean;
  stopped: boolean;
}
function fakeSource(): FakeSource {
  const s: FakeSource = {
    buffer: null,
    started: false,
    stopped: false,
    onended: null,
    connect() {},
    start() {
      s.started = true;
    },
    stop() {
      s.stopped = true;
    },
  };
  return s;
}

// Minimal AudioContext stand-in exposing only what the player touches.
class FakeAudio implements AudioContextLike {
  currentTime = 0;
  destination: unknown = {};
  gains: GainLike[] = [];
  sources: FakeSource[] = [];
  createGain(): GainLike {
    const g = fakeGain();
    this.gains.push(g);
    return g;
  }
  createBuffer(channels: number, length: number, _sampleRate: number): AudioBufferLike {
    const data = Array.from({ length: channels }, () => new Float32Array(length));
    return { getChannelData: (c: number) => data[c] };
  }
  createBufferSource(): AudioBufferSourceLike {
    const s = fakeSource();
    this.sources.push(s);
    return s;
  }
  suspended = 0;
  resumed = 0;
  async suspend(): Promise<void> {
    this.suspended++;
  }
  async resume(): Promise<void> {
    this.resumed++;
  }
}

// A small mono PCM DTO (2 i16-LE samples).
function pcmDto(pts_ms: number): PcmDto {
  return {
    channels: 1,
    sample_rate: 48000,
    pts_ms,
    // two samples: 0x0100 (256) and 0x0200 (512), little-endian.
    samples_b64: b64([0x00, 0x01, 0x00, 0x02]),
  };
}

// In-process event bus matching the injected `subscribe` shape.
function makeBus() {
  const cbs: Record<string, (p: unknown) => void> = {};
  const subscribe = <T,>(event: string, cb: (p: T) => void): Promise<() => void> => {
    cbs[event] = cb as (p: unknown) => void;
    return Promise.resolve(() => {
      delete cbs[event];
    });
  };
  const emit = (event: string, payload: unknown): void => cbs[event]?.(payload);
  return { subscribe, emit, has: (e: string) => e in cbs };
}

// base64 of raw bytes (Buffer exists in node; the player decodes portably).
function b64(bytes: number[]): string {
  return Buffer.from(Uint8Array.from(bytes)).toString("base64");
}

// A tiny 2x2 I420 frame DTO: luma 4 bytes, chroma 1x1 -> 1 byte each.
function frameDto(pts_ms: number): I420FrameDto {
  return {
    width: 2,
    height: 2,
    pts_ms,
    y_b64: b64([10, 20, 30, 40]),
    u_b64: b64([128]),
    v_b64: b64([128]),
  };
}

// ---- A/V sync ------------------------------------------------------------

test("releases video frames by pts against the audio clock, in order", () => {
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
  player.play();

  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  bus.emit(EVT_VIDEO_FRAME, frameDto(100));
  bus.emit(EVT_VIDEO_FRAME, frameDto(200));

  // Clock at 0: only the pts=0 frame is due; the others are future-held.
  clock = 0;
  player.tick();
  assert.strictEqual(drawn.length, 1);
  assert.strictEqual(drawn[0].pts_ms, 0);

  // 50ms < 100ms (minus tolerance): pts=100 frame is still held.
  clock = 0.05;
  player.tick();
  assert.strictEqual(drawn.length, 1, "future frame held");

  // Clock reaches 100ms: that frame releases.
  clock = 0.1;
  player.tick();
  assert.strictEqual(drawn.length, 2);
  assert.strictEqual(drawn[1].pts_ms, 100);

  // Clock reaches 200ms: last frame releases, in order.
  clock = 0.2;
  player.tick();
  assert.strictEqual(drawn.length, 3);
  assert.strictEqual(drawn[2].pts_ms, 200);
});

test("drops stale frames when the audio clock has jumped past them", () => {
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
  player.play();

  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  bus.emit(EVT_VIDEO_FRAME, frameDto(100));

  // Audio is now well past both frames; keep up by drawing the latest due
  // frame (pts=100) and dropping the stale pts=0 frame.
  clock = 0.2;
  player.tick();
  assert.strictEqual(drawn.length, 1, "only the latest due frame is drawn");
  assert.strictEqual(drawn[0].pts_ms, 100);
  assert.strictEqual(player.stats().dropped, 1, "the stale frame is counted dropped");
});

test("video syncs to elapsed time from playback start, not the raw clock (no burst)", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const drawn: YuvFrame[] = [];
  // Playback begins at a NONZERO wall-clock time (e.g. the app has been running 10s).
  let clock = 10;
  const player = createPlayer({
    audio,
    renderer: (f) => drawn.push(f),
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => clock,
  });
  player.play();

  // The first audio chunk establishes the playback origin at clock=10, and still
  // feeds the WebAudio graph.
  bus.emit(EVT_VIDEO_AUDIO, pcmDto(0));
  assert.ok(audio.sources.length >= 1, "audio fed into the WebAudio graph");
  assert.ok(audio.sources[0].started, "audio source scheduled");

  // Window-relative REAL video pts: a frame at 0ms and a frame at 1000ms.
  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  bus.emit(EVT_VIDEO_FRAME, frameDto(1000));

  // elapsed = 0: only the pts=0 frame is due. The OLD raw-clock code compared
  // 1000/1000=1 <= clock=10 and would have BURST both frames immediately.
  clock = 10;
  player.tick();
  assert.strictEqual(drawn.length, 1, "no burst: the 1000ms frame is held");
  assert.strictEqual(drawn[0].pts_ms, 0);

  // elapsed = 0.5s: the 1000ms frame is still held.
  clock = 10.5;
  player.tick();
  assert.strictEqual(drawn.length, 1, "frame at 1000ms held until ~1s elapsed");

  // elapsed = 1.0s: the 1000ms frame releases in sync with the audio clock.
  clock = 11.0;
  player.tick();
  assert.strictEqual(drawn.length, 2);
  assert.strictEqual(drawn[1].pts_ms, 1000);
  assert.strictEqual(player.stats().dropped, 0, "frames paced (not burst), nothing dropped");
});

test("video-only: the first frame establishes the playback origin", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const drawn: YuvFrame[] = [];
  let clock = 5; // nonzero origin, no audio at all
  const player = createPlayer({
    audio,
    renderer: (f) => drawn.push(f),
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => clock,
  });
  player.play();

  bus.emit(EVT_VIDEO_FRAME, frameDto(0)); // sets playbackStart = 5
  bus.emit(EVT_VIDEO_FRAME, frameDto(500));

  clock = 5; // elapsed 0
  player.tick();
  assert.strictEqual(drawn.length, 1, "only the pts=0 frame is due (no burst)");

  clock = 5.5; // elapsed 0.5s
  player.tick();
  assert.strictEqual(drawn.length, 2, "the 500ms frame releases at ~0.5s elapsed");
  assert.strictEqual(drawn[1].pts_ms, 500);
});

test("seek resets the playback origin for the new window", () => {
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
  player.play();

  // First window establishes origin at clock=0.
  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  clock = 0;
  player.tick();
  assert.strictEqual(drawn.length, 1);

  // Seek; the new window's first frame arrives at a later wall-clock time and must
  // re-establish the origin there (so its window-relative pts=0 is due immediately,
  // not treated as 20s in the past).
  player.seek(9999);
  clock = 20;
  bus.emit(EVT_VIDEO_FRAME, frameDto(0)); // new window, sets playbackStart = 20
  clock = 20;
  player.tick();
  assert.strictEqual(drawn.length, 2, "the new window's first frame is due at its origin");
  assert.strictEqual(player.stats().dropped, 0, "no stale drop from the stale origin");
});

// ---- volume --------------------------------------------------------------

test("setVolume clamps to [0,1] and drives the GainNode + persists", () => {
  const audio = new FakeAudio();
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: makeBus().subscribe,
    reducedMotion: true,
  });
  const gain = audio.gains[0];

  player.setVolume(0.5);
  assert.strictEqual(gain.gain.value, 0.5);
  assert.strictEqual(player.volume, 0.5, "preference persists");

  player.setVolume(2);
  assert.strictEqual(gain.gain.value, 1, "clamped to max 1");
  assert.strictEqual(player.volume, 1);

  player.setVolume(-3);
  assert.strictEqual(gain.gain.value, 0, "clamped to min 0");
  assert.strictEqual(player.volume, 0);
});

test("setVolume(NaN) leaves a finite gain (no NaN poisoning)", () => {
  const audio = new FakeAudio();
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: makeBus().subscribe,
    reducedMotion: true,
  });
  const gain = audio.gains[0];
  player.setVolume(0.7);
  player.setVolume(NaN);
  assert.ok(Number.isFinite(gain.gain.value), "gain stays finite");
  assert.ok(Number.isFinite(player.volume), "stored volume stays finite");
  assert.strictEqual(gain.gain.value, 0, "non-finite falls back to the low bound");
});

// ---- playback rate -------------------------------------------------------

test("setRate clamps to [0.5, 2.0] and stores the preference", () => {
  const player = createPlayer({
    audio: new FakeAudio(),
    renderer: () => {},
    subscribe: makeBus().subscribe,
    reducedMotion: true,
  });
  player.setRate(1.5);
  assert.strictEqual(player.rate, 1.5);
  player.setRate(9);
  assert.strictEqual(player.rate, 2.0, "clamped to 2.0");
  player.setRate(0.1);
  assert.strictEqual(player.rate, 0.5, "clamped to 0.5");
});

test("setRate(NaN) leaves a finite rate (no NaN poisoning)", () => {
  const player = createPlayer({
    audio: new FakeAudio(),
    renderer: () => {},
    subscribe: makeBus().subscribe,
    reducedMotion: true,
  });
  player.setRate(1.25);
  player.setRate(NaN);
  assert.ok(Number.isFinite(player.rate), "rate stays finite");
  assert.strictEqual(player.rate, 0.5, "non-finite falls back to the low bound");
});

// ---- reduced motion ------------------------------------------------------

test("reducedMotion blocks autoplay until an explicit play()", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const drawn: YuvFrame[] = [];
  const player = createPlayer({
    audio,
    renderer: (f) => drawn.push(f),
    subscribe: bus.subscribe,
    reducedMotion: true,
  });

  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  player.tick();
  assert.strictEqual(player.isPlaying(), false, "no autoplay under reduced motion");
  assert.strictEqual(drawn.length, 0, "nothing drawn while paused");

  player.play();
  player.tick();
  assert.strictEqual(player.isPlaying(), true);
  assert.strictEqual(drawn.length, 1, "explicit play() releases the due frame");
});

test("without reducedMotion the first frame autostarts playback", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const drawn: YuvFrame[] = [];
  const player = createPlayer({
    audio,
    renderer: (f) => drawn.push(f),
    subscribe: bus.subscribe,
    reducedMotion: false,
  });

  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  assert.strictEqual(player.isPlaying(), true, "autoplay on first frame");
  player.tick();
  assert.strictEqual(drawn.length, 1);
});

// ---- decoded-frame ring --------------------------------------------------

test("ring is bounded, evicts oldest, and scrubTo draws the nearest frame", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const drawn: YuvFrame[] = [];
  const player = createPlayer({
    audio,
    renderer: (f) => drawn.push(f),
    subscribe: bus.subscribe,
    reducedMotion: true, // no autoplay/tick draws; isolate the ring
    ringCapacity: 3,
  });

  // Push 5 frames; the ring should retain only the most recent 3 (200/300/400).
  for (const p of [0, 100, 200, 300, 400]) bus.emit(EVT_VIDEO_FRAME, frameDto(p));
  assert.strictEqual(drawn.length, 0, "paused: nothing drawn yet");

  // Nearest to 290 among {200,300,400} is 300.
  player.scrubTo(290);
  assert.strictEqual(drawn.length, 1);
  assert.strictEqual(drawn[0].pts_ms, 300);

  // 0 and 100 were evicted; nearest to 0 among {200,300,400} is 200.
  player.scrubTo(0);
  assert.strictEqual(drawn[1].pts_ms, 200);
});

// ---- bounded pending queue (D-7) -----------------------------------------

test("bounds the pending queue: a burst beyond the cap drops the oldest", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const drawn: YuvFrame[] = [];
  let clock = 0;
  const player = createPlayer({
    audio,
    renderer: (f) => drawn.push(f),
    subscribe: bus.subscribe,
    reducedMotion: true, // no autoplay/tick drain — isolate the bound
    pendingCapacity: 4,
    audioClock: () => clock,
  });

  // A burst of 10 frames at increasing window-relative pts. reducedMotion holds the
  // tick loop, so they all land in pending and the cap must shed the 6 oldest.
  for (let i = 0; i < 10; i++) bus.emit(EVT_VIDEO_FRAME, frameDto(i * 10));
  assert.strictEqual(player.stats().dropped, 6, "6 oldest dropped to keep the newest 4");

  // Drain far in the future: only the latest DUE frame is drawn (catch-up), the other 3
  // retained are dropped as stale — the queue never grew unbounded.
  player.play();
  clock = 1000;
  player.tick();
  assert.strictEqual(drawn.length, 1, "one frame drawn after catch-up");
  assert.strictEqual(drawn[0].pts_ms, 90, "the NEWEST retained frame survives");
  assert.strictEqual(player.stats().dropped, 9, "6 over-cap + 3 stale = 9 dropped");
});

test("under the pending cap nothing is dropped and sync is intact", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const drawn: YuvFrame[] = [];
  let clock = 0;
  const player = createPlayer({
    audio,
    renderer: (f) => drawn.push(f),
    subscribe: bus.subscribe,
    reducedMotion: false,
    pendingCapacity: 8,
    audioClock: () => clock,
  });
  player.play();
  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  bus.emit(EVT_VIDEO_FRAME, frameDto(100));
  clock = 0;
  player.tick();
  assert.strictEqual(drawn.length, 1, "pts=0 due, pts=100 held");
  clock = 0.1;
  player.tick();
  assert.strictEqual(drawn.length, 2, "pts=100 releases in sync");
  assert.strictEqual(player.stats().dropped, 0, "nothing dropped under the cap");
});

// ---- seek ----------------------------------------------------------------

test("seek clears the pending queue and notifies onSeek", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const drawn: YuvFrame[] = [];
  let seeked = -1;
  let clock = 0;
  const player = createPlayer({
    audio,
    renderer: (f) => drawn.push(f),
    subscribe: bus.subscribe,
    reducedMotion: false,
    audioClock: () => clock,
    onSeek: (pts) => (seeked = pts),
  });
  player.play();

  bus.emit(EVT_VIDEO_FRAME, frameDto(0));
  bus.emit(EVT_VIDEO_FRAME, frameDto(100));
  player.seek(5000);
  assert.strictEqual(seeked, 5000, "onSeek invoked with target");

  // Queue was cleared by seek: ticking past old pts draws nothing.
  clock = 0.2;
  player.tick();
  assert.strictEqual(drawn.length, 0, "pending frames cleared on seek");
});

test("seek stops in-flight audio sources so they don't overlap the new window", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: bus.subscribe,
    reducedMotion: false,
  });

  // Two PCM chunks get scheduled; their source nodes are live.
  bus.emit(EVT_VIDEO_AUDIO, pcmDto(0));
  bus.emit(EVT_VIDEO_AUDIO, pcmDto(100));
  assert.strictEqual(audio.sources.length, 2);
  assert.ok(audio.sources.every((s) => s.started && !s.stopped), "both scheduled, none stopped yet");

  player.seek(5000);
  assert.ok(audio.sources.every((s) => s.stopped), "seek stops every in-flight source");
});

test("dispose stops in-flight audio sources", () => {
  const bus = makeBus();
  const audio = new FakeAudio();
  const player = createPlayer({
    audio,
    renderer: () => {},
    subscribe: bus.subscribe,
    reducedMotion: false,
  });
  bus.emit(EVT_VIDEO_AUDIO, pcmDto(0));
  assert.strictEqual(audio.sources.length, 1);
  player.dispose();
  assert.ok(audio.sources[0].stopped, "dispose stops the live source");
});

// ---- dispose -------------------------------------------------------------

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

test("dispose unsubscribes all events", async () => {
  const bus = makeBus();
  const player = createPlayer({
    audio: new FakeAudio(),
    renderer: () => {},
    subscribe: bus.subscribe,
    reducedMotion: true,
  });
  // Let the subscribe promises resolve so unlisten handlers are registered.
  await Promise.resolve();
  assert.strictEqual(bus.has(EVT_VIDEO_FRAME), true);
  player.dispose();
  await Promise.resolve();
  assert.strictEqual(bus.has(EVT_VIDEO_FRAME), false, "events torn down");
});
