import "media-chrome";
import { call, on } from "../core/rpc.ts";
import { streamSrc } from "./video-src.ts";
import { serial } from "../core/serial.ts";
import {
  createYuvRenderer,
  WebglUnavailable,
  WebglProgramError,
  type YuvRenderer,
} from "../core/webgl-yuv.ts";
import {
  createPlayer,
  EVT_VIDEO_FRAME,
  type Player,
  type PlayerPhase,
  type YuvFrame,
  type I420FrameDto,
  type AudioContextLike,
} from "../core/player.ts";
import type { VideoInfo } from "../core/types.ts";

// Sandboxed-video CHROME (Gate 5.3). Pure UI, OUTSIDE the TCB.
//
// <video-player file-id="…"> is the user-facing transport for one decrypted
// video. The backend worker (Gate 4.x) streams ALREADY-decoded, ALREADY-
// validated I420 frames + i16-LE PCM + player-state phases over Tauri events;
// core/player.ts does A/V sync into a <canvas> (createYuvRenderer) + WebAudio
// graph. This component owns:
//   * a focusable, labeled media region (WCAG 2.4.3) + an aria-live status line,
//   * keyboard-operable, labeled transport controls (play/pause, a played-vs-
//     loaded scrubber, volume + mute, playback rate),
//   * a DEFAULT-OFF hardware-decode waiver with an unmistakable text warning,
//   * non-color-only (glyph + TEXT + aria-live) state for every PlayerPhase plus
//     a "decode worker pending" badge,
//   * honest teardown — cancel_video + dispose the player/renderer/AudioContext.
//
// The authed commands (open_video / video_seek / video_set_volume / cancel_video)
// go through the shared serial() queue, like every other reauth-bound UI call.
// No keys cross this layer; frames/PCM are already validated upstream.

// Tauri lower-cases the kebab variant tag; phase code -> visible label. Each
// label carries a glyph AND text so state is never conveyed by colour alone
// (WCAG 1.4.1). `error` is formatted separately (it carries a sanitized code).
const STATE_LABEL: Record<string, string> = {
  buffering: "⏳ Buffering…",
  playing: "▶ Playing",
  stalled: "⏸ Stalled — waiting for data",
  "codec-unavailable": "⚠ Codec unavailable — the secure decode worker is not present",
};

const RATES = [0.5, 0.75, 1, 1.25, 1.5, 2];

export class VideoPlayer extends HTMLElement {
  private _fileId = "";
  private reqId = "";
  private player: Player | null = null;
  private renderer: YuvRenderer | null = null;
  private audio: AudioContext | null = null;
  private unframe: (() => void) | null = null;
  private ticker: ReturnType<typeof setInterval> | null = null;
  private opened = false;
  private disposed = false;

  // Playback bookkeeping for the played-vs-loaded scrubber.
  private playedMs = 0; // pts of the frame currently presented (drawn)
  private loadedMs = 0; // furthest pts received so far (buffered frontier)
  private fragments = 0; // count of received frames/chunks (loaded proxy)
  private dragging = false; // true while the user is operating the scrubber
  // Hardware-decode waiver — DEFAULT OFF. STORED-ONLY preference stub: there is
  // no backend HW-decode path (wiring one is out of scope), so this is written
  // but intentionally never read; the secure software-decode path always stays
  // on. Kept so the preference + its warning have a home for a future HW path.
  private hwWaiver = false;
  private lastVol = 1; // volume to restore from mute
  private uninfo: (() => void) | null = null;
  private durationMs = 0;

  // PREVIEW MODE (Gate 6): when set, the player drives the local preview_video
  // path (decode of the author's STAGED canonical content — no server fetch, no
  // decrypt) instead of open_video. Set by the upload screen's preview surface.
  private _previewJob = "";

  // True when the native <video> + Media Chrome path is active (view path only;
  // the author-preview path keeps the confined-decode canvas engine).
  private native = false;

  // file-id may be supplied as a property (media-viewer sets it) or attribute.
  set fileId(v: string) {
    this._fileId = v;
    this.setAttribute("file-id", v);
  }
  get fileId(): string {
    return this._fileId || this.getAttribute("file-id") || "";
  }

  // preview-job may be supplied as a property (upload screen) or attribute.
  set previewJob(v: string) {
    this._previewJob = v;
    this.setAttribute("preview-job", v);
  }
  get previewJob(): string {
    return this._previewJob || this.getAttribute("preview-job") || "";
  }

  connectedCallback() {
    // VIEW path → native <video> + Media Chrome. Author PREVIEW (previewJob)
    // keeps the existing confined-decode canvas engine below (spec: reversal is
    // view-only).
    if (!this.previewJob) { this.connectNative(); return; }
    // ---- existing confined-preview setup continues UNCHANGED below ----
    this.reqId = this.fileId;
    // Static chrome skeleton — NO dynamic interpolation into innerHTML (XSS
    // guard). All dynamic text below goes through textContent/setAttribute.
    this.innerHTML = `
      <section id="vp-region" tabindex="-1" role="region" aria-label="Video player">
        <p id="vp-status" role="status" aria-live="polite">Loading…</p>
        <span id="vp-badge" class="vp-badge">⏳ Decode worker pending</span>
        <div class="vp-stage"><canvas id="vp-canvas" width="640" height="360"></canvas></div>
        <div class="vp-controls">
          <button id="vp-play" type="button" aria-label="Play">▶</button>
          <label class="vp-field">Seek
            <input id="vp-scrub" type="range" min="0" max="0" step="100" value="0"
              aria-label="Seek position" aria-valuemin="0" aria-valuemax="0" aria-valuenow="0" />
          </label>
          <progress id="vp-loaded" class="vp-loaded" aria-label="Loaded" max="1" value="0"></progress>
          <span id="vp-time" class="vp-time">0:00 / 0:00</span>
          <button id="vp-mute" type="button" aria-label="Mute">\u{1F50A}</button>
          <label class="vp-field">Volume
            <input id="vp-vol" type="range" min="0" max="100" value="100" aria-label="Volume" />
          </label>
          <label class="vp-field">Speed
            <select id="vp-rate" aria-label="Playback rate">
              <option value="0.5">0.5×</option>
              <option value="0.75">0.75×</option>
              <option value="1" selected>1×</option>
              <option value="1.25">1.25×</option>
              <option value="1.5">1.5×</option>
              <option value="2">2×</option>
            </select>
          </label>
          <label class="vp-field vp-hw">
            <input id="vp-hw" type="checkbox" /> Allow hardware decode (advanced)
          </label>
          <p id="vp-hw-warn" class="vp-warn" role="note" hidden>
            ⚠ Warning: enabling hardware / OS bitstream decode trades the sandbox
            containment that confines this video for battery and performance. It is
            not recommended — the secure software-decode path stays on by default.
          </p>
        </div>
      </section>`;

    (this.querySelector("#vp-region") as HTMLElement).focus();

    // The renderer must come up before we ask the backend for frames; a WebView
    // with no WebGL gets an honest codec-unavailable state, not a black canvas.
    const canvas = this.querySelector("#vp-canvas") as HTMLCanvasElement;
    try {
      this.renderer = createYuvRenderer(canvas);
    } catch (e) {
      if (e instanceof WebglUnavailable) {
        this.setPhase({ phase: "codec-unavailable" });
      } else if (e instanceof WebglProgramError) {
        this.setPhase({ phase: "error", code: "renderer" });
      } else {
        this.setPhase({ phase: "error", code: "renderer" });
      }
      // No renderer → nothing to play. Disable the transport so a keyboard/SR
      // user cannot tab to a dead (focusable-but-inert) Play/scrub/volume control;
      // the aria-live status already explains the state.
      this.disableControls();
      return;
    }

    // AudioContext is the A/V master clock + the volume graph.
    try {
      this.audio = new AudioContext();
    } catch {
      this.setPhase({ phase: "error", code: "audio" });
      this.renderer.dispose();
      this.renderer = null;
      this.disableControls(); // no audio graph → same: no inert focusable chrome
      return;
    }

    const reducedMotion =
      document.documentElement.hasAttribute("data-reduced-motion") ||
      (typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches);

    // Record the pts of each presented frame so the scrubber shows the true
    // PLAYED position (the player drops stale frames, so the drawn frame ~= now).
    let lastW = 0;
    let lastH = 0;
    const drawSink = {
      draw: (f: YuvFrame) => {
        if (!this.renderer) return;
        if (f.width !== lastW || f.height !== lastH) {
          lastW = f.width;
          lastH = f.height;
          this.renderer.resize(f.width, f.height);
        }
        this.playedMs = f.pts_ms;
        this.renderer.draw(f);
      },
    };

    this.player = createPlayer({
      // The real AudioContext is structurally a superset of AudioContextLike
      // (its source.onended takes an Event arg the player never passes); the cast
      // is sound because the player only ever assigns/clears onended.
      audio: this.audio as unknown as AudioContextLike,
      renderer: drawSink,
      subscribe: on,
      reducedMotion,
      onPhase: (p) => this.setPhase(p),
      requestWindow: (pts) => {
        if (this.previewJob) {
          void serial(() => call<void>("preview_seek", { jobId: this.previewJob, ptsMs: Math.round(pts) })).catch(() => {});
        } else {
          void serial(() => call<void>("video_seek", { fileId: this.reqId, ptsMs: Math.round(pts) })).catch(() => {});
        }
      },
    });

    // Track the buffered frontier independently (the player holds future frames
    // in its pending queue; we count every received frame as a loaded fragment).
    void on<I420FrameDto>(EVT_VIDEO_FRAME, (f) => {
      this.fragments++;
      if (f.pts_ms > this.loadedMs) this.loadedMs = f.pts_ms;
      this.hideBadge();
    }).then((un) => {
      // If we were torn down before the subscription resolved, unsubscribe now.
      if (this.disposed) un();
      else this.unframe = un;
    });

    void on<VideoInfo>("maxsecu://video-info", (info) => {
      this.player?.setDuration(info.duration_ms);
      this.durationMs = info.duration_ms;
    }).then((un) => { if (this.disposed) un(); else this.uninfo = un; });

    this.wireControls();
    this.ticker = setInterval(() => this.refreshScrubber(), 250);

    if (reducedMotion) {
      (this.querySelector("#vp-status") as HTMLElement).textContent =
        "Reduced motion: press Play to start.";
    }

    void this.open();
  }

  disconnectedCallback() {
    this.disposed = true;
    if (this.ticker !== null) {
      clearInterval(this.ticker);
      this.ticker = null;
    }
    this.unframe?.();
    this.unframe = null;
    this.uninfo?.();
    this.uninfo = null;
    this.player?.dispose();
    this.player = null;
    this.renderer?.dispose();
    this.renderer = null;
    // Drop the backend session (zeroizes the content subkey) — fire and forget.
    // The preview path registers no backend VideoJob (it decodes the staged
    // plaintext one-shot), so there is nothing to cancel there.
    if (this.opened && this.reqId && !this.previewJob) {
      void serial(() => call<void>("cancel_video", { fileId: this.reqId })).catch(() => {});
    }
    const audio = this.audio;
    this.audio = null;
    if (audio) void audio.close().catch(() => {});
  }

  // ---- native view path (stream:// Range protocol + Media Chrome) ----------

  private connectNative() {
    this.native = true;
    this.reqId = this.fileId;
    // Static chrome — NO dynamic interpolation into innerHTML (XSS guard).
    this.innerHTML = `
      <section id="vp-region" tabindex="-1" role="region" aria-label="Video player">
        <p id="vp-status" role="status" aria-live="polite" hidden></p>
        <media-controller style="width:100%;aspect-ratio:16/9;background:#000">
          <video slot="media" playsinline preload="metadata"></video>
          <media-control-bar>
            <media-play-button></media-play-button>
            <media-time-range></media-time-range>
            <media-time-display showduration></media-time-display>
            <media-mute-button></media-mute-button>
            <media-volume-range></media-volume-range>
            <media-fullscreen-button></media-fullscreen-button>
          </media-control-bar>
        </media-controller>
      </section>`;
    (this.querySelector("#vp-region") as HTMLElement).focus();
    // TEMP DIAGNOSTIC: surface CSP violations (which are otherwise invisible w/o
    // devtools) to the backend log so we can see if the stream URL is blocked.
    dlog(`connectNative id=${this.reqId} media-controller-defined=${!!customElements.get("media-controller")}`);
    document.addEventListener("securitypolicyviolation", (e) => {
      dlog(`CSP-VIOLATION directive=${e.violatedDirective} blocked=${e.blockedURI}`);
    });
    const video = this.querySelector("video") as HTMLVideoElement;
    video.addEventListener("error", () => {
      const code = video.error?.code ?? -1;
      dlog(`video-error code=${code} src=${video.currentSrc || video.src}`);
      const s = this.querySelector("#vp-status") as HTMLElement | null;
      if (s) {
        s.textContent = "⚠ This video could not be played.";
        s.removeAttribute("hidden");
      }
    });
    ["loadstart", "loadedmetadata", "canplay", "playing", "stalled"].forEach((ev) =>
      video.addEventListener(ev, () => dlog(`video-${ev} t=${video.currentTime.toFixed(2)}`)),
    );
    void this.openNative(video);
  }

  private async openNative(video: HTMLVideoElement) {
    try {
      this.opened = true;
      dlog(`openNative: calling open_video id=${this.reqId}`);
      // open_video registers the decrypt-while-stream session (register-only +
      // total-length probe). Only decrypted plaintext crosses the stream:// seam.
      await serial(() => call<void>("open_video", { fileId: this.reqId }));
      // Point the native element at the stream:// range protocol; the browser
      // owns demux/decode/seek/buffer/sync.
      const url = streamSrc(this.reqId);
      dlog(`openNative: open_video OK, setting src=${url}`);
      video.src = url;
    } catch (x) {
      dlog(`openNative: open_video ERR code=${phaseCode(x)}`);
      const s = this.querySelector("#vp-status") as HTMLElement | null;
      if (s) {
        s.textContent = `⚠ Error: ${phaseCode(x)}`;
        s.removeAttribute("hidden");
      }
    }
  }

  // ---- backend session (preview/legacy path) --------------------------------

  private async open() {
    try {
      this.opened = true;
      if (this.previewJob) {
        // Local preview-before-upload decode of the author's STAGED canonical
        // content (no server, no decrypt). Same frame/phase events as open_video.
        await serial(() => call<void>("preview_video", { jobId: this.previewJob }));
      } else {
        await serial(() => call<void>("open_video", { fileId: this.reqId }));
      }
    } catch (x) {
      this.setPhase({ phase: "error", code: phaseCode(x) });
    }
  }

  // ---- state machine (non-colour-only: glyph + text + aria-live) ----------

  private setPhase(p: PlayerPhase) {
    const status = this.querySelector("#vp-status") as HTMLElement | null;
    if (!status) return;
    if (p.phase === "error") {
      status.textContent =
        p.code === "cancelled" ? "⏹ Stopped." : `⚠ Error: ${p.code}`;
    } else {
      status.textContent = STATE_LABEL[p.phase] ?? p.phase;
    }
    // Any real phase means the worker answered — retire the pending badge.
    if (p.phase !== "codec-unavailable") this.hideBadge();
    if (p.phase === "playing") this.setPlayGlyph(this.player?.isPlaying() ?? true);
  }

  private hideBadge() {
    const badge = this.querySelector("#vp-badge") as HTMLElement | null;
    if (badge && !badge.hidden) badge.hidden = true;
  }

  // Failure path: mark every transport control disabled + aria-disabled so no
  // focusable-but-inert control is left for keyboard/SR users when there is no
  // renderer/audio to drive. (The label strings stay in source for the lint.)
  private disableControls() {
    this.querySelectorAll<HTMLElement>(
      "#vp-play, #vp-scrub, #vp-loaded, #vp-mute, #vp-vol, #vp-rate, #vp-hw",
    ).forEach((el) => {
      (el as HTMLButtonElement | HTMLInputElement | HTMLSelectElement).disabled = true;
      el.setAttribute("aria-disabled", "true");
    });
  }

  // ---- controls -----------------------------------------------------------

  private wireControls() {
    const play = this.querySelector("#vp-play") as HTMLButtonElement;
    play.addEventListener("click", () => {
      const p = this.player;
      if (!p) return;
      if (p.isPlaying()) {
        p.pause();
        this.setPlayGlyph(false);
      } else {
        p.play();
        this.setPlayGlyph(true);
      }
    });

    const scrub = this.querySelector("#vp-scrub") as HTMLInputElement;
    scrub.addEventListener("input", () => {
      this.dragging = true;
      scrub.setAttribute("aria-valuenow", scrub.value);
      this.updateTime(Number(scrub.value), this.loadedMs);
    });
    // 'change' commits the seek (fires for pointer release AND arrow/Home/End).
    // player.seek() calls requestWindow() internally, which issues preview_seek
    // or video_seek as appropriate — no separate call needed here.
    scrub.addEventListener("change", () => {
      this.dragging = false;
      const pts = Math.max(0, Math.round(Number(scrub.value)));
      this.player?.seek(pts);
    });

    const vol = this.querySelector("#vp-vol") as HTMLInputElement;
    vol.addEventListener("input", () => this.applyVolume(Number(vol.value) / 100));

    const mute = this.querySelector("#vp-mute") as HTMLButtonElement;
    mute.addEventListener("click", () => {
      const cur = this.player?.volume ?? this.lastVol;
      if (cur > 0) {
        this.lastVol = cur;
        this.applyVolume(0);
        mute.setAttribute("aria-label", "Unmute");
        mute.textContent = "\u{1F507}";
        vol.value = "0";
      } else {
        this.applyVolume(this.lastVol || 1);
        mute.setAttribute("aria-label", "Mute");
        mute.textContent = "\u{1F50A}";
        vol.value = String(Math.round((this.lastVol || 1) * 100));
      }
    });

    const rate = this.querySelector("#vp-rate") as HTMLSelectElement;
    rate.addEventListener("change", () => {
      const r = Number(rate.value);
      if (RATES.includes(r)) this.player?.setRate(r);
    });

    const hw = this.querySelector("#vp-hw") as HTMLInputElement;
    const warn = this.querySelector("#vp-hw-warn") as HTMLElement;
    hw.checked = false; // belt-and-braces: the waiver is DEFAULT OFF.
    hw.addEventListener("change", () => {
      // STUB: stores the preference + surfaces the warning. There is no backend
      // HW-decode path — wiring one is OUT OF SCOPE; the sandbox path stays on.
      this.hwWaiver = hw.checked;
      warn.hidden = !hw.checked;
      const status = this.querySelector("#vp-status") as HTMLElement;
      if (hw.checked) {
        status.textContent =
          "⚠ Hardware decode requested — not recommended; sandbox containment reduced.";
      }
    });
  }

  private applyVolume(gain: number) {
    const g = Number.isFinite(gain) ? Math.min(1, Math.max(0, gain)) : 0;
    this.player?.setVolume(g);
    // The preview path holds no backend session/gain to persist; volume is local.
    if (!this.previewJob) {
      void serial(() => call<void>("video_set_volume", { fileId: this.reqId, gain: g })).catch(() => {});
    }
  }

  private setPlayGlyph(playing: boolean) {
    const play = this.querySelector("#vp-play") as HTMLButtonElement | null;
    if (!play) return;
    play.textContent = playing ? "⏸" : "▶";
    play.setAttribute("aria-label", playing ? "Pause" : "Play");
  }

  // The scrubber thumb sits at the engine's current play position; max is the
  // total clip duration from the engine (set via VideoInfo on open).
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

  private updateTime(playedMs: number, loadedMs: number) {
    const t = this.querySelector("#vp-time") as HTMLElement | null;
    if (!t) return;
    const text = `${fmt(playedMs)} / ${fmt(loadedMs)}`;
    t.textContent = text;
    const scrub = this.querySelector("#vp-scrub") as HTMLInputElement | null;
    scrub?.setAttribute("aria-valuetext", text);
  }
}

// TEMP DIAGNOSTIC: fire-and-forget a line to the backend log (<appdir>/logs/
// stream.log) so we can trace the native player without devtools. Remove later.
function dlog(msg: string): void {
  void call<void>("stream_debug_log", { msg }).catch(() => {});
}

// Sanitized error -> a short stable code for the status line (no oracle).
function phaseCode(x: unknown): string {
  if (x && typeof x === "object" && "code" in x) {
    const c = (x as { code?: unknown }).code;
    if (typeof c === "string") return c;
  }
  return "open_failed";
}

// milliseconds -> "M:SS" for the time readout.
function fmt(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}:${r < 10 ? "0" : ""}${r}`;
}

customElements.define("video-player", VideoPlayer);
