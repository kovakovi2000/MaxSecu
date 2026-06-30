import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import type { UploadKind, UploadPreview } from "../core/types.ts";
import { normalizeOptions, resolutionForPreset, suggestKbps } from "../core/transcode-opts.ts";
import type { Bitrate, Resolution } from "../core/transcode-opts.ts";
import "./video-player.ts";
import type { VideoPlayer } from "./video-player.ts";

// Upload (spec §5): choose Image (file path), Blog (body text) or Video (a real
// video file path + a resolution/bitrate menu) + title/tags → Preview
// (stage_upload — transcodes/encrypts LOCALLY, NO network write) → Confirm
// (confirm_upload — staged → resumable PUT → finalize, routed through serial()).
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
  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="up-h">
        <h1 id="up-h">Upload a post</h1>
        <form id="up-form">
          <label>Type
            <select name="kind">
              <option value="image">Image</option>
              <option value="blog">Blog</option>
              <option value="video">Video</option>
            </select></label>
          <div id="path-row">
            <label>Image file path
              <input name="path" type="text" autocomplete="off" /></label>
            <button id="pick-image" type="button" aria-label="Browse for an image file">Browse…</button>
          </div>
          <label id="body-row" hidden>Post body
            <textarea name="content" rows="6"></textarea></label>
          <div id="video-row" hidden>
            <label>Video file
              <input name="vpath" type="text" autocomplete="off" /></label>
            <button id="pick-video" type="button" aria-label="Browse for a video file">Browse…</button>
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
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();
    const form = this.querySelector("#up-form") as HTMLFormElement;
    const kind = form.querySelector('select[name="kind"]') as HTMLSelectElement;
    const pathRow = this.querySelector("#path-row") as HTMLElement;
    const bodyRow = this.querySelector("#body-row") as HTMLElement;
    const videoRow = this.querySelector("#video-row") as HTMLElement;
    const syncKind = () => {
      const k = kind.value;
      pathRow.hidden = k !== "image";
      bodyRow.hidden = k !== "blog";
      videoRow.hidden = k !== "video";
    };
    kind.addEventListener("change", syncKind);
    syncKind();

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

    // "Browse…" opens the native OS file dialog (pick_file) and drops the chosen
    // path into the matching text field — no bytes cross here, only a path.
    const pathInput = form.querySelector('input[name="path"]') as HTMLInputElement;
    const vpathInput = form.querySelector('input[name="vpath"]') as HTMLInputElement;
    const pickInto = async (input: HTMLInputElement, extensions: string[]) => {
      try {
        const p = await call<string | null>("pick_file", { extensions });
        if (p) input.value = p;
      } catch (x) {
        (this.querySelector("#up-status") as HTMLElement).textContent =
          errMsg(x, "Could not open the file dialog.");
      }
    };
    this.querySelector("#pick-image")?.addEventListener("click", () => {
      void pickInto(pathInput, ["png", "jpg", "jpeg", "webp", "gif", "bmp"]);
    });
    this.querySelector("#pick-video")?.addEventListener("click", () => {
      void pickInto(vpathInput, ["mp4", "mov", "mkv", "webm", "avi", "m4v", "mpg", "mpeg", "wmv", "flv", "ts"]);
    });

    form.addEventListener("submit", (e) => this.onPreview(e, form));
  }

  private async onPreview(e: Event, form: HTMLFormElement) {
    e.preventDefault();
    const status = this.querySelector("#up-status")!;
    status.textContent = "Preparing…";
    const d = new FormData(form);
    const kind = (d.get("kind") as UploadKind) ?? "image";
    const tags = String(d.get("tags") ?? "").split(",").map((t) => t.trim()).filter((t) => t.length > 0);
    const req: Record<string, unknown> = { kind, title: d.get("title"), tags };
    if (kind === "blog") {
      req.content = d.get("content");
    } else if (kind === "video") {
      const vpath = String(d.get("vpath") ?? "").trim();
      if (!vpath) {
        status.textContent = "Choose a video file.";
        return;
      }
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
      req.path = vpath;
      req.options = normalizeOptions({ resolution, bitrate });
    } else {
      req.path = d.get("path");
    }
    try {
      const preview = await call<UploadPreview>("stage_upload", { req });
      this.renderPreview(preview);
      status.textContent =
        preview.file_type === "video" ? "Transcoded — preview below before uploading." : "Ready to upload.";
    } catch (x) {
      status.textContent = errMsg(x, "Could not prepare the upload.");
    }
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
    status.textContent = "Uploading… (see the uploads tray)";
    try {
      await serial(() => call<string>("confirm_upload", { req: { job_id: jobId } }));
      status.textContent = "Upload complete.";
      (this.querySelector("#up-preview") as HTMLElement).replaceChildren();
    } catch (x) {
      btn.disabled = false;
      status.textContent = errMsg(x, "Upload failed.");
    }
  }
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("upload-screen", UploadScreen);
