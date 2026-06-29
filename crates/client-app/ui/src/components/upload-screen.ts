import { call } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import type { UploadKind, UploadPreview } from "../core/types.ts";
import "./state-badge.ts";

// Upload (spec §5): choose Image (file path) or Blog (body text) + title/tags →
// Preview (stage_upload — encrypts locally, NO network write) → Confirm
// (confirm_upload — staged → resumable PUT → finalize, routed through serial()).
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
            </select></label>
          <label id="path-row">Image file path
            <input name="path" type="text" autocomplete="off" /></label>
          <label id="body-row" hidden>Post body
            <textarea name="content" rows="6"></textarea></label>
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
    const syncKind = () => {
      const isBlog = kind.value === "blog";
      pathRow.hidden = isBlog;
      bodyRow.hidden = !isBlog;
    };
    kind.addEventListener("change", syncKind);
    syncKind();
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
    if (kind === "blog") req.content = d.get("content"); else req.path = d.get("path");
    try {
      const preview = await call<UploadPreview>("stage_upload", { req });
      this.renderPreview(preview);
      status.textContent = "Ready to upload.";
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
    if (p.thumbnail_b64) {
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
