// Sandboxed-video PLAYER binding (Gate 5.2). Pure UI, OUTSIDE the TCB.
//
// The backend video worker (Gate 4.x) emits ALREADY-decoded, ALREADY-validated
// streams over Tauri events: I420 video frames, interleaved i16-LE PCM audio,
// and player-state phases. This module consumes those three streams and:
//   * does A/V SYNC — the AUDIO clock is master; video frames are released by
//     their pts against that clock (future frames held, stale frames dropped so
//     video never lags audio),
//   * pushes PCM into a tiny WebAudio graph through a GainNode (volume),
//   * keeps a BOUNDED in-RAM decoded-frame ring for instant local scrub, and
//   * exposes the player controls the <video-player> component (5.3) drives.
//
// Everything browser-only (WebAudio, requestAnimationFrame, the YUV renderer,
// the Tauri event bus) is behind a SMALL injectable interface so this runs under
// node:test with plain fakes. There are no keys at this layer.

import { on } from "./rpc.ts";
import type { YuvFrame as RenderYuvFrame } from "./webgl-yuv.ts";

// ---- backend event names + DTOs -----------------------------------------

export const EVT_PLAYER_STATE = "maxsecu://player-state";
export const EVT_VIDEO_FRAME = "maxsecu://video-frame";
export const EVT_VIDEO_AUDIO = "maxsecu://video-audio";

// One decoded I420 frame, planes base64-encoded (Y full-res, U/V half-res).
export interface I420FrameDto {
  width: number;
  height: number;
  pts_ms: number;
  y_b64: string;
  u_b64: string;
  v_b64: string;
}

// One chunk of interleaved i16-LE PCM, base64-encoded.
export interface PcmDto {
  channels: number;
  sample_rate: number;
  pts_ms: number;
  samples_b64: string;
}

// Backend player phase (kebab-tagged), surfaced to the component via onPhase.
// `gap` is a BENIGN, non-terminal notice that the decode dropped `skipped` fragment(s)
// or frame(s) (resilient-driver respawn, or the D-7 in-flight bound) — count-only, no
// oracle. The player keeps going; the component may show a brief "skipped" hint.
export type PlayerPhase =
  | { phase: "buffering" | "playing" | "stalled" | "codec-unavailable" }
  | { phase: "gap"; skipped: number }
  | { phase: "error"; code: string };

// A decoded frame: render planes plus the presentation timestamp we sync on.
export interface YuvFrame extends RenderYuvFrame {
  pts_ms: number;
}

// ---- injectable browser surfaces (kept deliberately small) ---------------

// Just the GainNode bits we touch: a writable gain value and a connect().
export interface GainLike {
  gain: { value: number };
  connect(destination: unknown): void;
}

export interface AudioBufferLike {
  getChannelData(channel: number): Float32Array;
}

export interface AudioBufferSourceLike {
  buffer: AudioBufferLike | null;
  connect(destination: unknown): void;
  start(when?: number): void;
  // Halt a scheduled/playing source (used to kill in-flight audio on seek).
  stop(when?: number): void;
  // Fires when the buffer finishes; we use it to release the live handle.
  onended?: (() => void) | null;
}

// The minimal AudioContext surface the player needs. The real WebAudio
// AudioContext is structurally assignable to this.
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

// The frame sink: either the 5.1 YuvRenderer ({ draw }) or a bare function.
export type FrameSink = ((frame: YuvFrame) => void) | { draw(frame: YuvFrame): void };

// The event subscription shape; rpc.ts `on` is the default.
export type Subscribe = <T>(event: string, cb: (payload: T) => void) => Promise<() => void>;

export interface PlayerOptions {
  audio: AudioContextLike;
  renderer: FrameSink;
  // Defaults to rpc.ts `on` (Tauri listen) when omitted.
  subscribe?: Subscribe;
  // When true the player will NOT autostart on the first frame; the user must
  // call play() (honours prefers-reduced-motion).
  reducedMotion: boolean;
  // Max decoded frames retained for instant local scrub (default 16).
  ringCapacity?: number;
  // Max decoded frames held in the pending (awaiting-pts) queue (default 96). A whole
  // window's frames arrive together (a burst); this BOUNDS the WebView's decoded-frame
  // memory so an extreme (4K+) clip can't accumulate unbounded I420 planes. Over the cap
  // the OLDEST pending frame is dropped (counted toward dropped) — the same catch-up
  // posture tick() already uses for stale frames.
  // A COUNT cap (not bytes) is safe here because the upstream client-app already enforces
  // a BYTE cap (MAX_FRAME_BUF_BYTES = 64 MiB) before frames cross the seam: at 8K only
  // ~1 frame per fragment survives, ~5 at 4K, so `pending` only ever approaches this count
  // at lower resolutions where each frame's absolute footprint (and thus 96 frames) is
  // modest. The two caps compose to bound the total decoded-frame footprint end to end.
  pendingCapacity?: number;
  // Master clock in SECONDS; defaults to audio.currentTime. Injectable so tests
  // drive sync deterministically.
  audioClock?: () => number;
  // Upper bound for the GainNode value (default 1).
  maxGain?: number;
  // Sync slack in ms: a frame is "due" once clock >= pts - tolerance (default 8).
  toleranceMs?: number;
  // Called by seek() so the component can request the new window from the
  // backend (calling `video_seek` is the COMPONENT's job, not this module's).
  onSeek?: (pts_ms: number) => void;
  // Receives every player-state phase from the backend.
  onPhase?: (phase: PlayerPhase) => void;
}

export interface Player {
  // Start playback (and the rAF pacing loop when in a browser).
  play(): void;
  // Pause playback; the audio clock and queues are retained.
  pause(): void;
  // Reset local scheduler + ring for a new window and notify onSeek(pts_ms).
  seek(pts_ms: number): void;
  // Set volume; clamped to [0, maxGain] and written to the GainNode.
  setVolume(gain: number): void;
  // Set playback rate; clamped to [0.5, 2.0].
  setRate(rate: number): void;
  // Draw the ringed frame nearest pts_ms for instant local scrub (no decode).
  scrubTo(pts_ms: number): void;
  // Advance the scheduler once: release/drop frames vs the audio clock. The rAF
  // loop calls this; tests call it directly for deterministic stepping.
  tick(): void;
  // Tear down: unsubscribe all events, stop pacing, clear queues + ring.
  dispose(): void;
  isPlaying(): boolean;
  // Frames drawn vs dropped (catch-up) for diagnostics/tests.
  stats(): { drawn: number; dropped: number };
  readonly volume: number;
  readonly rate: number;
}

// ---- portable base64 (atob may be absent under node) ---------------------

let b64Lut: Int16Array | null = null;
function base64Lut(): Int16Array {
  if (b64Lut) return b64Lut;
  const t = new Int16Array(256).fill(-1);
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (let i = 0; i < chars.length; i++) t[chars.charCodeAt(i)] = i;
  return (b64Lut = t);
}

function decodeBase64(input: string): Uint8Array {
  const t = base64Lut();
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < input.length; i++) {
    const c = input.charCodeAt(i);
    if (c === 61) break; // '=' padding
    const v = t[c];
    if (v < 0) continue; // skip whitespace / non-base64
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

// Decode base64 of interleaved i16-LE PCM into an Int16Array (endian-explicit).
function decodeI16Le(b64: string): Int16Array {
  const u8 = decodeBase64(b64);
  const n = u8.length >> 1;
  const out = new Int16Array(n);
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  for (let i = 0; i < n; i++) out[i] = dv.getInt16(i * 2, true);
  return out;
}

// ---- player --------------------------------------------------------------

export function createPlayer(opts: PlayerOptions): Player {
  const audio = opts.audio;
  const subscribe: Subscribe = opts.subscribe ?? on;
  const reducedMotion = opts.reducedMotion;
  const ringCapacity = Math.max(1, opts.ringCapacity ?? 16);
  const pendingCapacity = Math.max(1, opts.pendingCapacity ?? 96);
  const maxGain = opts.maxGain ?? 1;
  const toleranceSec = (opts.toleranceMs ?? 8) / 1000;
  const audioClock = opts.audioClock ?? (() => audio.currentTime);
  const renderer = opts.renderer;
  const drawFrame: (f: YuvFrame) => void =
    typeof renderer === "function" ? renderer : (f) => renderer.draw(f);

  // Volume GainNode wired gain -> destination once.
  const gain = audio.createGain();
  gain.connect(audio.destination);

  // Pending frames awaiting their pts (arrival order == increasing pts), and a
  // bounded ring of recently-decoded frames for instant local scrub.
  const pending: YuvFrame[] = [];
  const ring: YuvFrame[] = [];
  // Live (scheduled but not-yet-finished) audio source nodes, so a seek/dispose
  // can stop in-flight buffers instead of letting them play over the new window.
  const liveSources = new Set<AudioBufferSourceLike>();

  let playing = false;
  let started = false; // first-frame autostart latch
  let disposed = false;
  let volume = clamp(1, 0, maxGain);
  let rate = 1;
  let drawnCount = 0;
  let droppedCount = 0;
  let nextAudioTime = 0; // playout cursor for the audio graph (seconds)
  // The audio-clock reading captured when playback begins (first scheduled audio
  // chunk, or first frame when video-only). The audio is master and is scheduled
  // gaplessly from here, so video frames sync against ELAPSED time since this origin
  // (audioClock() - playbackStart) rather than the raw clock — otherwise window-relative
  // pts (which start near 0) would all read as "due" against a nonzero wall clock and
  // the whole window would burst then stall. Reset on seek (a new window). null until
  // the first frame/audio establishes the origin.
  let playbackStart: number | null = null;

  gain.gain.value = volume;

  // Capture the playback-start origin exactly once, at the first audio chunk or frame.
  function ensurePlaybackStart(): void {
    if (playbackStart === null) playbackStart = audioClock();
  }

  // rAF pacing when in a browser; under node the loop is inert and tests drive
  // tick() directly.
  const raf: ((cb: () => void) => number) | null =
    typeof requestAnimationFrame !== "undefined" ? (cb) => requestAnimationFrame(cb) : null;
  const caf: ((id: number) => void) | null =
    typeof cancelAnimationFrame !== "undefined" ? (id) => cancelAnimationFrame(id) : null;
  let rafId: number | null = null;

  function loop(): void {
    tick();
    if (playing && raf) rafId = raf(loop);
    else rafId = null;
  }
  function startLoop(): void {
    if (raf && rafId === null && playing) rafId = raf(loop);
  }
  function stopLoop(): void {
    if (caf && rafId !== null) caf(rafId);
    rafId = null;
  }

  function pushRing(frame: YuvFrame): void {
    ring.push(frame);
    if (ring.length > ringCapacity) ring.shift();
  }

  function onFrame(dto: I420FrameDto): void {
    if (disposed) return;
    // Establish the playback origin on the first frame (covers the video-only case;
    // for A/V the first audio chunk usually sets it first — whichever fires first wins).
    ensurePlaybackStart();
    const frame: YuvFrame = {
      width: dto.width,
      height: dto.height,
      pts_ms: dto.pts_ms,
      y: decodeBase64(dto.y_b64),
      u: decodeBase64(dto.u_b64),
      v: decodeBase64(dto.v_b64),
    };
    pending.push(frame);
    // Bound the pending queue: a window's frames arrive together (a burst), so without a
    // cap the WebView could accumulate unbounded decoded I420 planes for an extreme (4K+)
    // clip. Over the cap, drop the OLDEST pending frame (count it) — the catch-up posture
    // tick() uses for stale frames. The client-app already bounds frames-per-fragment
    // before they cross the seam; this is the WebView-side backstop (D-7).
    while (pending.length > pendingCapacity) {
      pending.shift();
      droppedCount++;
    }
    pushRing(frame);
    // Autostart on the first frame unless reduced-motion asked us to hold.
    if (!started) {
      started = true;
      if (!reducedMotion) play();
    }
  }

  function onAudio(dto: PcmDto): void {
    if (disposed || dto.channels <= 0) return;
    // Audio is master: the first scheduled chunk establishes the playback origin the
    // video syncs against.
    ensurePlaybackStart();
    const samples = decodeI16Le(dto.samples_b64);
    const frames = Math.floor(samples.length / dto.channels);
    if (frames <= 0) return;
    const buf = audio.createBuffer(dto.channels, frames, dto.sample_rate);
    for (let c = 0; c < dto.channels; c++) {
      const out = buf.getChannelData(c);
      for (let i = 0; i < frames; i++) out[i] = samples[i * dto.channels + c] / 32768;
    }
    const src = audio.createBufferSource();
    src.buffer = buf;
    src.connect(gain);
    // Retain the live handle so seek()/dispose() can stop it; release it when the
    // buffer finishes on its own.
    liveSources.add(src);
    src.onended = () => liveSources.delete(src);
    // Schedule contiguously after whatever is already queued (gapless playout).
    const startAt = Math.max(audio.currentTime, nextAudioTime);
    src.start(startAt);
    nextAudioTime = startAt + frames / dto.sample_rate;
  }

  // Stop every in-flight audio source and forget it. Guarded so stopping an
  // already-finished source can't throw.
  function stopAllSources(): void {
    for (const src of liveSources) {
      try {
        src.stop();
      } catch {
        // already stopped/ended — nothing to do
      }
    }
    liveSources.clear();
  }

  function onState(phase: PlayerPhase): void {
    if (disposed) return;
    opts.onPhase?.(phase);
  }

  // ---- A/V sync scheduler ----
  // Audio is master. Walk the pending queue: future frames (pts beyond clock +
  // tolerance) are HELD; among consecutive DUE frames only the latest is drawn
  // and the earlier ones are DROPPED, so video catches up to audio.
  function tick(): void {
    if (!playing || disposed) return;
    // Sync against ELAPSED time since playback start, not the raw clock, so the
    // window-relative pts (which start near 0) line up with the audio that began at
    // playbackStart. If no frame/audio has set the origin yet, set it now.
    if (playbackStart === null) playbackStart = audioClock();
    const now = audioClock() - playbackStart;
    let toDraw: YuvFrame | null = null;
    while (pending.length > 0) {
      const head = pending[0];
      const ptsSec = head.pts_ms / 1000;
      if (ptsSec > now + toleranceSec) break; // future: hold
      if (toDraw !== null) droppedCount++; // previous due frame is stale
      toDraw = pending.shift() as YuvFrame;
    }
    if (toDraw) {
      drawnCount++;
      drawFrame(toDraw);
    }
  }

  // ---- controls ----

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

  function seek(pts_ms: number): void {
    // Drop the local window; the component will request a fresh one. Stop any
    // already-scheduled audio so it doesn't bleed over the new window.
    pending.length = 0;
    ring.length = 0;
    nextAudioTime = 0;
    // A new window restarts the timeline: re-establish the playback origin from the
    // first frame/audio of the new window.
    playbackStart = null;
    stopAllSources();
    opts.onSeek?.(pts_ms);
  }

  function setVolume(g: number): void {
    volume = clamp(g, 0, maxGain);
    gain.gain.value = volume;
  }

  function setRate(r: number): void {
    // NOTE: `rate` is currently STORED-ONLY here. Actual playback-rate
    // application (audio resample / video scheduling cadence) is wired in Task
    // 5.3 / the backend; this binding intentionally keeps it inert.
    rate = clamp(r, 0.5, 2.0);
  }

  function scrubTo(pts_ms: number): void {
    if (ring.length === 0) return;
    let best = ring[0];
    let bestDelta = Math.abs(best.pts_ms - pts_ms);
    for (let i = 1; i < ring.length; i++) {
      const d = Math.abs(ring[i].pts_ms - pts_ms);
      if (d < bestDelta) {
        bestDelta = d;
        best = ring[i];
      }
    }
    drawFrame(best);
  }

  // ---- event wiring + teardown ----

  const unlisteners: Array<() => void> = [];
  function track(p: Promise<() => void>): void {
    p.then((un) => {
      if (disposed) un();
      else unlisteners.push(un);
    });
  }
  track(subscribe<I420FrameDto>(EVT_VIDEO_FRAME, onFrame));
  track(subscribe<PcmDto>(EVT_VIDEO_AUDIO, onAudio));
  track(subscribe<PlayerPhase>(EVT_PLAYER_STATE, onState));

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    playing = false;
    stopLoop();
    stopAllSources();
    for (const un of unlisteners) un();
    unlisteners.length = 0;
    pending.length = 0;
    ring.length = 0;
  }

  return {
    play,
    pause,
    seek,
    setVolume,
    setRate,
    scrubTo,
    tick,
    dispose,
    isPlaying: () => playing,
    stats: () => ({ drawn: drawnCount, dropped: droppedCount }),
    get volume() {
      return volume;
    },
    get rate() {
      return rate;
    },
  };
}

// NaN-safe clamp: a non-finite input (NaN/Infinity) falls back to the low bound
// so it never poisons the GainNode value or the stored rate.
function clamp(v: number, lo: number, hi: number): number {
  if (!Number.isFinite(v)) return lo;
  return v < lo ? lo : v > hi ? hi : v;
}
