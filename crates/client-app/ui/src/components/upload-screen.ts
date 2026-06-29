import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import type { UploadKind, UploadPreview } from "../core/types.ts";
import "./video-player.ts";
import type { VideoPlayer } from "./video-player.ts";

// Upload (spec §5): choose Image (file path), Blog (body text) or Video (a raw-
// frame MXRAWV01 source — file path or a generated sample) + title/tags → Preview
// (stage_upload — transcodes/encrypts LOCALLY, NO network write) → Confirm
// (confirm_upload — staged → resumable PUT → finalize, routed through serial()).
//
// For a Video the stage runs the CONFINED transcode worker; the returned job holds
// the canonical AV1/CMAF plaintext + fragment index, which the preview surface
// renders by driving <video-player preview-job=…> against the local preview_video
// path (decode of the staged content — no server, no decrypt). The author sees the
// transcoded result BEFORE confirming the upload.
//
// Accessible: landmark, labelled controls, role=status live region.
export class UploadScreen extends HTMLElement {
  // The generated/loaded MXRAWV01 raw-frame source for a video stage (base64).
  private sampleSourceB64 = "";

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
          <label id="path-row">Image file path
            <input name="path" type="text" autocomplete="off" /></label>
          <label id="body-row" hidden>Post body
            <textarea name="content" rows="6"></textarea></label>
          <div id="video-row" hidden>
            <label>Raw-frame (MXRAWV01) source file path
              <input name="vpath" type="text" autocomplete="off" /></label>
            <button id="up-gen" type="button">Generate a sample clip</button>
            <p id="up-gen-status" role="status" aria-live="polite"></p>
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

    const gen = this.querySelector("#up-gen") as HTMLButtonElement;
    gen.addEventListener("click", () => {
      this.sampleSourceB64 = makeSampleSourceB64();
      (this.querySelector("#up-gen-status") as HTMLElement).textContent =
        "Sample clip ready — choose Preview to transcode it.";
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
      if (this.sampleSourceB64) req.source_b64 = this.sampleSourceB64;
      else if (vpath) req.path = vpath;
      else {
        status.textContent = "Choose a raw-frame source file or generate a sample clip.";
        return;
      }
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
      this.sampleSourceB64 = "";
    } catch (x) {
      btn.disabled = false;
      status.textContent = errMsg(x, "Upload failed.");
    }
  }
}

// Build a tiny MXRAWV01 raw-frame source (the transcode worker's documented
// default-path container): 24-byte header (magic + w/h/frames/fps LE) then tightly
// packed RGB24 frames. Standard-base64 encoded for the `source_b64` request field.
function makeSampleSourceB64(): string {
  const w = 16, h = 16, frames = 3, fps = 10;
  const header = 24;
  const buf = new Uint8Array(header + w * h * 3 * frames);
  buf.set([0x4d, 0x58, 0x52, 0x41, 0x57, 0x56, 0x30, 0x31], 0); // "MXRAWV01"
  const dv = new DataView(buf.buffer);
  dv.setUint32(8, w, true);
  dv.setUint32(12, h, true);
  dv.setUint32(16, frames, true);
  dv.setUint32(20, fps, true);
  let p = header;
  for (let f = 0; f < frames; f++) {
    for (let i = 0; i < w * h; i++) {
      buf[p++] = (i + f) & 0xff; // R
      buf[p++] = Math.floor(i / w) & 0xff; // G
      buf[p++] = (f * 40) & 0xff; // B
    }
  }
  let s = "";
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
  return btoa(s);
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("upload-screen", UploadScreen);
