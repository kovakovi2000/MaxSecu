import "media-chrome";
import { call } from "../core/rpc.ts";
import { streamSrc, previewSrc } from "./video-src.ts";
import { serial } from "../core/serial.ts";
import { settingsStore } from "../core/settings.ts";
import { updateSettings } from "../core/settings.ts";

// Pure: clamp a raw volume into [0,1] (NaN → 1). Mirrors the backend clamp so the
// UI and settings.json agree.
export function clampVolume(v: number): number {
  if (Number.isNaN(v)) return 1;
  return Math.min(1, Math.max(0, v));
}

// Sandboxed-video CHROME (Gate 5.3 / native-decode pivot). Pure UI, OUTSIDE the TCB.
//
// <video-player file-id="…"> is the user-facing transport for one decrypted
// video. Playback goes through a native <video> element (the WebView2 decoder)
// driven by Media Chrome, fed over the stream:// byte-range protocol — the
// browser owns demux/decode/seek/buffer/sync; only decrypted plaintext bytes
// ever cross the stream:// seam. This component owns:
//   * a focusable, labeled media region (WCAG 2.4.3) + an aria-live status line,
//   * the native Media Chrome transport (play/pause, scrubber, mute/volume,
//     fullscreen) — keyboard-operable and labeled by the library,
//   * a user-facing error message when the native decoder reports an error,
//   * honest teardown — cancel_video to drop the backend session.
//
// The one authed command left (open_video) goes through the shared serial()
// queue, like every other reauth-bound UI call. No keys cross this layer.

// DOM-safe base: HTMLElement in the WebView (identical to `extends HTMLElement`),
// a dummy stand-in under node:test (which has no DOM) so this module — and its
// pure `clampVolume` export — can be imported without a ReferenceError. No
// instance is ever constructed off-DOM, so the stand-in's members are never hit.
const ElementBase: typeof HTMLElement =
  typeof HTMLElement !== "undefined"
    ? HTMLElement
    : (class {} as unknown as typeof HTMLElement);

export class VideoPlayer extends ElementBase {
  private _fileId = "";
  private reqId = "";
  private opened = false;
  private disposed = false;

  // PREVIEW MODE (Gate 6): when set, the player points straight at the local
  // preview namespace (the author's STAGED canonical content — no server
  // fetch, no decrypt) instead of calling open_video. Set by the upload
  // screen's preview surface.
  private _previewJob = "";

  // True when the native <video> + Media Chrome path is active.
  private native = false;

  // True when mounted inside an embedded (Stacked bundle-member) media-viewer.
  // Embedded players must not steal focus — each member that loads would
  // otherwise scroll-jump the page. Set from the `embedded` attribute on mount.
  private embedded = false;

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
    this.connectNative();
  }

  disconnectedCallback() {
    this.disposed = true;
    // Drop the backend session (zeroizes the content subkey) — fire and forget.
    // The preview path registers no backend VideoJob (it streams the staged
    // plaintext directly), so there is nothing to cancel there.
    if (this.opened && this.reqId && !this.previewJob) {
      void serial(() => call<void>("cancel_video", { fileId: this.reqId })).catch(() => {});
    }
  }

  // ---- native view path (stream:// Range protocol + Media Chrome) ----------

  private connectNative() {
    this.native = true;
    this.reqId = this.fileId;
    // Static chrome — NO dynamic interpolation into innerHTML (XSS guard).
    this.innerHTML = `
      <section id="vp-region" tabindex="-1" role="region" aria-label="Video player">
        <p id="vp-status" role="status" aria-live="polite" hidden></p>
        <media-controller autohide="2" style="width:100%;aspect-ratio:16/9;background:#000">
          <video slot="media" playsinline preload="metadata"></video>
          <media-loading-indicator slot="centered-chrome" noautohide></media-loading-indicator>
          <media-control-bar>
            <media-play-button></media-play-button>
            <media-time-range></media-time-range>
            <media-time-display showduration></media-time-display>
            <media-mute-button></media-mute-button>
            <media-volume-range></media-volume-range>
            <media-playback-rate-button></media-playback-rate-button>
            <media-fullscreen-button></media-fullscreen-button>
          </media-control-bar>
        </media-controller>
      </section>`;
    // Routed viewer: move focus to the media region (WCAG 2.4.3). Embedded
    // (Stacked bundle) instances must NOT — a loading member grabbing focus
    // scroll-jumps the page.
    this.embedded = this.hasAttribute("embedded");
    if (!this.embedded) {
      (this.querySelector("#vp-region") as HTMLElement).focus();
    }
    const video = this.querySelector("video") as HTMLVideoElement;
    // Restore persisted volume/mute (settings.json is the source of truth). Applied
    // after Media Chrome mounts so ours wins over its own localStorage copy.
    const pb = settingsStore.get().playback;
    video.volume = clampVolume(pb.volume);
    video.muted = pb.muted;
    let volTimer: ReturnType<typeof setTimeout> | undefined;
    video.addEventListener("volumechange", () => {
      // Debounce: persist (and patch the shared store) only after the drag settles,
      // so scrubbing the volume doesn't re-run the settings subscriber every tick.
      if (volTimer) clearTimeout(volTimer);
      volTimer = setTimeout(() => {
        const volume = clampVolume(video.volume);
        const muted = video.muted;
        settingsStore.patchLocal({ playback: { volume, muted } });
        void updateSettings({ playback: { volume, muted } }).catch(() => {});
      }, 400);
    });
    video.addEventListener("error", () => {
      const s = this.querySelector("#vp-status") as HTMLElement | null;
      if (s) {
        s.textContent = "⚠ This video could not be played.";
        s.removeAttribute("hidden");
      }
    });
    if (this.previewJob) {
      // Author preview: serve the OWN staged fMP4 by range — no open_video, no
      // cancel_video (the staged job is owned by the upload flow). Point the
      // element straight at the preview namespace.
      video.src = previewSrc(this.previewJob);
    } else {
      void this.openNative(video); // view path: open_video (register+probe) then streamSrc
    }
  }

  private async openNative(video: HTMLVideoElement) {
    try {
      this.opened = true;
      // open_video registers the decrypt-while-stream session (register-only +
      // total-length probe). Only decrypted plaintext crosses the stream:// seam.
      await serial(() => call<void>("open_video", { fileId: this.reqId }));
      // Point the native element at the stream:// range protocol; the browser
      // owns demux/decode/seek/buffer/sync.
      video.src = streamSrc(this.reqId);
    } catch (x) {
      const s = this.querySelector("#vp-status") as HTMLElement | null;
      if (s) {
        s.textContent = `⚠ Error: ${phaseCode(x)}`;
        s.removeAttribute("hidden");
      }
    }
  }
}

// Sanitized error -> a short stable code for the status line (no oracle).
function phaseCode(x: unknown): string {
  if (x && typeof x === "object" && "code" in x) {
    const c = (x as { code?: unknown }).code;
    if (typeof c === "string") return c;
  }
  return "open_failed";
}

if (typeof customElements !== "undefined") {
  customElements.define("video-player", VideoPlayer);
}
