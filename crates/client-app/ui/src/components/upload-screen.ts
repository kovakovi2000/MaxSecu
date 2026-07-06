import { call, on } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { setBusy, clearBusy } from "../core/busy.ts";
import type { PreparePhase, UploadPreview } from "../core/types.ts";
import { detectKind } from "../core/composer.ts";
import type { MediaKind } from "../core/composer.ts";
import { normalizeOptions, resolutionForPreset, suggestKbps } from "../core/transcode-opts.ts";
import type { Bitrate, Resolution } from "../core/transcode-opts.ts";

// Human labels for the auto-detected file kind (shown next to the file field so
// the user sees what the post will be without choosing a type).
const DETECTED_LABEL: Record<MediaKind, string> = {
  image: "Image",
  video: "Video (will transcode)",
  generic: "File (download-only)",
};
import "./video-player.ts";
import type { VideoPlayer } from "./video-player.ts";
import "./bundle-composer.ts";

// Upload (spec §5): pick a File (its kind is AUTO-DETECTED from the extension —
// image / video / generic download-only; no manual type picker) or write a Text
// post + title/tags → Preview (stage_upload — transcodes/encrypts LOCALLY, NO
// network write) → Confirm (confirm_upload — staged → resumable PUT → finalize,
// routed through serial()). A detected video reveals the resolution/bitrate menu;
// anything not an image/video extension uploads as a generic download-only file.
//
// For a Video the stage runs the CONFINED ffmpeg ingest + transcode worker against
// the chosen real video file (only its PATH crosses the seam — no bytes); the
// returned job holds the canonical AV1/CMAF plaintext + fragment index, which the
// preview surface renders by driving <video-player preview-job=…> against the local
// preview_video path (decode of the staged content — no server, no decrypt). The
// author sees the transcoded result BEFORE confirming the upload.
//
// The resolution/bitrate menu builds a TranscodeOptions (see core/transcode-opts.ts)
// whose JSON shape matches the Rust `media-launcher::TranscodeOptions` enum exactly.
//
// Accessible: landmark, labelled controls, role=status live region.
export class UploadScreen extends HTMLElement {
  // Unlisten for the in-flight maxsecu://video-prepare subscription (null when
  // no transcode is running). Always cleared on completion/cancel/failure and on
  // teardown so no listener leaks.
  private prepareUnlisten: (() => void) | null = null;
  // The kind auto-detected from the chosen file's extension (image/video/generic).
  // Drives the video-shaping controls' visibility and the submit path. Recomputed
  // whenever the file path changes (browse or manual edit).
  private detectedKind: MediaKind = "image";

  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="up-h">
        <h1 id="up-h">Upload a post</h1>
        <div class="up-mode" role="group" aria-label="Post type">
          <button id="up-mode-single" type="button" class="up-mode-btn active" aria-pressed="true">Single post</button>
          <button id="up-mode-bundle" type="button" class="up-mode-btn" aria-pressed="false">New bundle</button>
        </div>
        <div id="up-single">
        <form id="up-form">
          <label>Post kind
            <select name="mode">
              <option value="file">File (auto-detected)</option>
              <option value="text">Text post</option>
            </select></label>
          <div id="file-row">
            <label>File
              <input name="path" type="text" autocomplete="off" /></label>
            <button id="pick-file" type="button" aria-label="Browse for a file">Browse…</button>
            <p id="up-detected" class="up-detected" aria-live="polite"></p>
          </div>
          <label id="body-row" hidden>Post body
            <textarea name="content" rows="6"></textarea></label>
          <div id="video-row" hidden>
            <label>Resolution
              <select name="resolution">
                <option value="original">Original (keep source)</option>
                <option value="2160">2160p (4K)</option>
                <option value="1440">1440p (QHD)</option>
                <option value="1080">1080p (Full HD)</option>
                <option value="720">720p (HD)</option>
                <option value="480">480p (SD)</option>
                <option value="custom">Custom…</option>
              </select></label>
            <div id="custom-res" hidden>
              <label>Custom width
                <input name="cw" type="number" min="2" max="7680" step="2" autocomplete="off" /></label>
              <label>Custom height
                <input name="ch" type="number" min="2" max="4320" step="2" autocomplete="off" /></label>
            </div>
            <label>Bitrate (kbps)
              <input name="kbps" type="number" min="64" max="200000" step="1" autocomplete="off" /></label>
            <label><input name="origbitrate" type="checkbox" checked /> Original bitrate</label>
          </div>
          <label>Title <input name="title" type="text" required autocomplete="off" /></label>
          <label>Tags (comma-separated) <input name="tags" type="text" autocomplete="off" /></label>
          <button type="submit">Preview</button>
        </form>
        <p id="up-status" role="status" aria-live="polite"></p>
        <div id="up-preview"></div>
        </div>
        <div id="up-bundle" hidden></div>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();

    // Mode toggle: "Single post" (the form above) vs "New bundle" (mount the
    // <bundle-composer> child region). upload-screen keeps the single #main
    // landmark; the composer brings its own aria-live status region.
    const single = this.querySelector("#up-single") as HTMLElement;
    const bundleMount = this.querySelector("#up-bundle") as HTMLElement;
    const singleBtn = this.querySelector("#up-mode-single") as HTMLButtonElement;
    const bundleBtn = this.querySelector("#up-mode-bundle") as HTMLButtonElement;
    const setMode = (mode: "single" | "bundle") => {
      const isBundle = mode === "bundle";
      single.hidden = isBundle;
      bundleMount.hidden = !isBundle;
      singleBtn.setAttribute("aria-pressed", String(!isBundle));
      bundleBtn.setAttribute("aria-pressed", String(isBundle));
      singleBtn.classList.toggle("active", !isBundle);
      bundleBtn.classList.toggle("active", isBundle);
      if (isBundle) {
        // Mount a fresh composer (its connectedCallback focuses its region).
        if (!bundleMount.querySelector("bundle-composer")) {
          bundleMount.appendChild(document.createElement("bundle-composer"));
        }
      } else {
        // Unmount so a not-yet-posted staged bundle is cancelled (disconnectedCallback).
        bundleMount.replaceChildren();
      }
    };
    singleBtn.addEventListener("click", () => setMode("single"));
    bundleBtn.addEventListener("click", () => setMode("bundle"));
    const form = this.querySelector("#up-form") as HTMLFormElement;
    const mode = form.querySelector('select[name="mode"]') as HTMLSelectElement;
    const fileRow = this.querySelector("#file-row") as HTMLElement;
    const bodyRow = this.querySelector("#body-row") as HTMLElement;
    const videoRow = this.querySelector("#video-row") as HTMLElement;
    const pathInput = form.querySelector('input[name="path"]') as HTMLInputElement;
    const detected = this.querySelector("#up-detected") as HTMLElement;
    // Auto-detect the picked file's kind (image/video/generic) from its extension —
    // no manual type picker. The video-shaping controls appear ONLY for a detected
    // video; a non-image/-video extension uploads as a generic download-only file.
    // "Text post" mode has no file (an explicit choice, since text can't be sniffed).
    const refresh = () => {
      const isText = mode.value === "text";
      fileRow.hidden = isText;
      bodyRow.hidden = !isText;
      const path = pathInput.value.trim();
      this.detectedKind = path ? detectKind(path) : "image";
      videoRow.hidden = isText || this.detectedKind !== "video";
      detected.textContent = isText || !path ? "" : `Detected: ${DETECTED_LABEL[this.detectedKind]}`;
    };
    mode.addEventListener("change", refresh);
    pathInput.addEventListener("input", refresh);
    refresh();

    // Resolution/bitrate menu wiring. Custom W/H are revealed only for "custom".
    // Changing resolution AWAY from Original auto-suggests a starting bitrate
    // (from the TARGET resolution's nominal dims at 30 fps — the source's real
    // dims/fps are unknown until staging) and unchecks "Original bitrate" so the
    // user can edit the kbps. Selecting Original re-checks it (keep source bitrate).
    const resSel = form.querySelector('select[name="resolution"]') as HTMLSelectElement;
    const customRes = this.querySelector("#custom-res") as HTMLElement;
    const cwInput = form.querySelector('input[name="cw"]') as HTMLInputElement;
    const chInput = form.querySelector('input[name="ch"]') as HTMLInputElement;
    const kbpsInput = form.querySelector('input[name="kbps"]') as HTMLInputElement;
    const origBitrate = form.querySelector('input[name="origbitrate"]') as HTMLInputElement;
    // Nominal 16:9 dims per height preset — only a starting suggestion source.
    const PRESET_DIMS: Record<string, { w: number; h: number }> = {
      "2160": { w: 3840, h: 2160 },
      "1440": { w: 2560, h: 1440 },
      "1080": { w: 1920, h: 1080 },
      "720": { w: 1280, h: 720 },
      "480": { w: 854, h: 480 },
    };
    const targetDims = (): { w: number; h: number } => {
      if (resSel.value === "custom") {
        return { w: Number(cwInput.value), h: Number(chInput.value) };
      }
      return PRESET_DIMS[resSel.value] ?? { w: 0, h: 0 };
    };
    const suggestBitrate = () => {
      const { w, h } = targetDims();
      kbpsInput.value = String(suggestKbps(w, h, 30));
      origBitrate.checked = false;
    };
    const onResolutionChange = () => {
      customRes.hidden = resSel.value !== "custom";
      if (resSel.value === "original") {
        origBitrate.checked = true; // Original resolution ⇒ keep source bitrate.
        return;
      }
      suggestBitrate();
    };
    resSel.addEventListener("change", onResolutionChange);
    // While in Custom, re-suggest the bitrate as the user enters/edits W×H.
    const onCustomDims = () => {
      if (resSel.value === "custom") suggestBitrate();
    };
    cwInput.addEventListener("input", onCustomDims);
    chInput.addEventListener("input", onCustomDims);
    customRes.hidden = resSel.value !== "custom";

    // "Browse…" opens the native OS file dialog (pick_file, ANY file) and drops the
    // chosen path into the field — no bytes cross here, only a path. Detection then
    // runs on the resulting value (reveals the video controls for a video, etc.).
    this.querySelector("#pick-file")?.addEventListener("click", async () => {
      try {
        const p = await call<string | null>("pick_file", { extensions: [] });
        if (p) {
          pathInput.value = p;
          refresh();
        }
      } catch (x) {
        (this.querySelector("#up-status") as HTMLElement).textContent =
          errMsg(x, "Could not open the file dialog.");
      }
    });

    form.addEventListener("submit", (e) => this.onPreview(e, form));
  }

  private async onPreview(e: Event, form: HTMLFormElement) {
    e.preventDefault();
    const status = this.querySelector("#up-status") as HTMLElement;
    const submitBtn = form.querySelector('button[type="submit"]') as HTMLButtonElement;
    status.textContent = "Preparing…";
    const d = new FormData(form);
    const mode = String(d.get("mode") ?? "file");
    const tags = String(d.get("tags") ?? "").split(",").map((t) => t.trim()).filter((t) => t.length > 0);
    const req: Record<string, unknown> = { title: d.get("title"), tags };
    if (mode === "text") {
      req.kind = "blog";
      req.content = d.get("content");
    } else {
      const path = String(d.get("path") ?? "").trim();
      if (!path) {
        status.textContent = "Choose a file.";
        return;
      }
      // Kind is AUTO-DETECTED from the file (image/video/generic) — no type picker.
      const kind = this.detectedKind;
      req.kind = kind;
      req.path = path;
      if (kind === "video") {
        // Build the transcode shaping options from the menu. The JSON shape mirrors
        // the Rust `TranscodeOptions` enum; normalizeOptions clamps as a UX nicety
        // (the Rust side ALWAYS re-clamps against the authoritative VideoBounds).
        const resVal = String(d.get("resolution") ?? "original");
        let resolution: Resolution;
        if (resVal === "original") {
          resolution = "Original";
        } else if (resVal === "custom") {
          resolution = { Custom: { width: Number(d.get("cw")), height: Number(d.get("ch")) } };
        } else {
          resolution = resolutionForPreset(resVal);
        }
        const bitrate: Bitrate = d.get("origbitrate") != null ? "Original" : { Kbps: Number(d.get("kbps")) };
        req.options = normalizeOptions({ resolution, bitrate });
        // Video: stage under a live transcode-progress + Cancel UI (own path).
        await this.previewVideo(req, status, submitBtn);
        return;
      }
    }
    try {
      const preview = await call<UploadPreview>("stage_upload", { req });
      this.renderPreview(preview);
      status.textContent = "Ready to upload.";
    } catch (x) {
      status.textContent = errMsg(x, "Could not prepare the upload.");
    }
  }

  // Video preview: stage the CONFINED ffmpeg ingest + transcode while surfacing
  // live progress (maxsecu://video-prepare) into the #up-status live region and a
  // labelled <progress>, with a Cancel button (cancel_video_prepare). The app is
  // marked busy for the duration so navigation is blocked; Cancel is the escape
  // hatch. Cancellation (the `cancelled` phase OR a stage_upload `code:"cancelled"`
  // rejection) returns the screen to idle with a neutral note — NOT an error.
  private async previewVideo(
    req: Record<string, unknown>,
    status: HTMLElement,
    submitBtn: HTMLButtonElement,
  ) {
    // Build the accessible progress + Cancel controls next to the live region.
    const box = document.createElement("div");
    box.id = "up-prepare";
    box.className = "up-prepare";
    const progress = document.createElement("progress");
    progress.id = "up-progress";
    progress.max = 100;
    progress.setAttribute("aria-label", "Transcode progress");
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.id = "up-cancel";
    cancelBtn.textContent = "Cancel";
    cancelBtn.addEventListener("click", () => {
      cancelBtn.disabled = true; // avoid a double-fire; terminal event/rejection drives the rest
      status.textContent = "Cancelling…";
      // The cancelled phase + the stage_upload rejection return us to idle.
      void call("cancel_video_prepare").catch(() => {});
    });
    box.append(progress, cancelBtn);
    status.after(box);
    submitBtn.disabled = true;
    setBusy("Transcoding video");

    let cancelledPhase = false;
    // Subscribe BEFORE staging so no early phase is missed. Render text via
    // textContent (no innerHTML) and drive the <progress> value/indeterminate.
    const unlisten = await on<PreparePhase>("maxsecu://video-prepare", (p) => {
      switch (p.phase) {
        case "transcoding":
          if (p.percent == null) {
            status.textContent = "Transcoding…";
            progress.removeAttribute("value"); // indeterminate
          } else {
            status.textContent = `Transcoding… ${p.percent}%`;
            progress.value = p.percent;
          }
          break;
        case "remuxing":
          status.textContent = "Re-muxing…";
          progress.removeAttribute("value");
          break;
        case "finalizing":
          status.textContent = "Finalizing…";
          progress.removeAttribute("value");
          break;
        case "sealing":
          // Post-transcode "Preparing preview" encrypt/digest pass over the whole file.
          if (p.percent == null) {
            status.textContent = "Preparing preview…";
            progress.removeAttribute("value"); // indeterminate
          } else {
            status.textContent = `Preparing preview… ${p.percent}%`;
            progress.value = p.percent;
          }
          break;
        case "cancelled":
          cancelledPhase = true; // benign terminal; teardown happens below
          break;
        case "failed":
          // Sanitized failure is surfaced via the stage_upload rejection path.
          break;
      }
    }).catch(() => null);
    this.prepareUnlisten = unlisten;

    try {
      const preview = await call<UploadPreview>("stage_upload", { req });
      this.teardownPrepare();
      submitBtn.disabled = false;
      this.renderPreview(preview);
      status.textContent = "Transcoded — preview below before uploading.";
    } catch (x) {
      this.teardownPrepare();
      submitBtn.disabled = false;
      if (cancelledPhase || isCancelledErr(x)) {
        status.textContent = "Transcode cancelled.";
      } else {
        status.textContent = errMsg(x, "Could not prepare the upload.");
      }
    }
  }

  // Unlisten the prepare subscription (if any), remove the progress/Cancel UI,
  // and clear the busy flag. Safe to call more than once.
  private teardownPrepare() {
    if (this.prepareUnlisten) {
      this.prepareUnlisten();
      this.prepareUnlisten = null;
    }
    this.querySelector("#up-prepare")?.remove();
    clearBusy();
  }

  disconnectedCallback() {
    // No listener leaks if the screen is torn down mid-transcode.
    this.teardownPrepare();
  }

  private renderPreview(p: UploadPreview) {
    const wrap = this.querySelector("#up-preview") as HTMLElement;
    wrap.replaceChildren();
    const h = document.createElement("h2");
    h.textContent = `Preview: ${p.title || "(untitled)"}`;
    wrap.appendChild(h);
    if (p.file_type === "video") {
      // WYSIWYG preview: decode the STAGED canonical content locally (preview_video)
      // before any upload. The player renders the transcoded result the viewer will
      // see, with no server fetch and no decrypt.
      const vp = document.createElement("video-player");
      (vp as unknown as VideoPlayer).previewJob = p.job_id;
      wrap.appendChild(vp);
    } else if (p.thumbnail_b64) {
      const img = document.createElement("img");
      img.src = `data:image/png;base64,${p.thumbnail_b64}`;
      img.alt = p.title ? `Thumbnail: ${p.title}` : "Thumbnail";
      wrap.appendChild(img);
    }
    const dl = document.createElement("dl");
    const add = (dt: string, dd: string) => {
      const a = document.createElement("dt"); a.textContent = dt;
      const b = document.createElement("dd"); b.textContent = dd;
      dl.append(a, b);
    };
    add("Type", p.file_type);
    add("Size", `${p.byte_size} bytes`);
    add("Chunks", String(p.total_chunks));
    if (p.tags.length) add("Tags", p.tags.map((t) => `#${t}`).join(" "));
    wrap.appendChild(dl);

    const confirm = document.createElement("button");
    confirm.textContent = "Confirm upload";
    confirm.addEventListener("click", () => this.onConfirm(p.job_id, confirm));
    wrap.appendChild(confirm);
  }

  private async onConfirm(jobId: string, btn: HTMLButtonElement) {
    const status = this.querySelector("#up-status")!;
    btn.disabled = true;
    // Mark busy for the whole upload so navigation is blocked until it settles.
    setBusy("Uploading");
    status.textContent = "Uploading… (see the uploads tray)";
    try {
      await serial(() => call<string>("confirm_upload", { req: { job_id: jobId } }));
      status.textContent = "Upload complete.";
      (this.querySelector("#up-preview") as HTMLElement).replaceChildren();
    } catch (x) {
      btn.disabled = false;
      status.textContent = errMsg(x, "Upload failed.");
    } finally {
      clearBusy();
    }
  }
}

// True when a rejection is the backend's user-initiated cancel (UiError code
// "cancelled") — treated as a return-to-idle, never an error toast/message.
function isCancelledErr(x: unknown): boolean {
  return (
    !!x && typeof x === "object" && "code" in x &&
    (x as { code?: unknown }).code === "cancelled"
  );
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("upload-screen", UploadScreen);
