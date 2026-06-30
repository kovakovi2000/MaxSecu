import { call, on } from "../core/rpc.ts";
import { serialPriority } from "../core/serial.ts";
import type { OpenedContent, FetchMsg } from "../core/types.ts";
import "./progress-meter.ts";
import "./skeleton-card.ts";
import "./video-player.ts";
import type { VideoPlayer } from "./video-player.ts";
import { toast } from "../core/toast.ts";

// Viewer (spec §5): renders one decrypted post. Image → data: URL <img>; blog →
// textContent (NEVER innerHTML). Subscribes to EVT_FETCH for live status. The
// decrypted content shown is the product; no keys cross the boundary. open_content
// is routed through the shared serial() queue (the backend re-auths per call and
// cannot run those concurrently with in-flight card decrypts).
export class MediaViewer extends HTMLElement {
  private unlisten: (() => void) | null = null;
  private reqId = "";

  async connectedCallback() {
    const params = new URLSearchParams(location.hash.split("?")[1] ?? "");
    const id = params.get("id") ?? "";
    const vParam = params.get("v");
    const version = vParam !== null ? Number(vParam) : undefined;
    this.reqId = id;
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="vw-h">
        <a href="#/feed">← Back to feed</a>
        <h1 id="vw-h">Loading…</h1>
        <p id="vw-status" role="status" aria-live="polite"></p>
        <progress-meter id="vw-meter" hidden></progress-meter>
        <div id="vw-body"></div>
        <dl id="vw-meta"></dl>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();

    const status = this.querySelector("#vw-status")!;
    const meter = this.querySelector("#vw-meter") as HTMLElement;
    this.unlisten = await on<FetchMsg>("maxsecu://fetch-state", (m) => {
      if (m.file_id !== id) return;
      if (m.phase === "fetching") {
        meter.setAttribute("value", String(m.fetched));
        meter.setAttribute("max", String(m.total));
        meter.hidden = false;
        status.textContent = "Fetching…";
      } else if (m.phase === "verifying") {
        status.textContent = "Verifying…";
      } else if (m.phase === "decrypting") {
        status.textContent = "Decrypting…";
      } else if (m.phase === "ready") {
        meter.hidden = true;
        status.textContent = "Ready.";
      } else if (m.phase === "failed") {
        meter.hidden = true;
        status.textContent = `Failed: ${m.code}`;
      }
    });

    (this.querySelector("#vw-body") as HTMLElement).appendChild(
      document.createElement("skeleton-card"),
    );

    try {
      const c = await serialPriority(() =>
        call<OpenedContent>("open_content", { req: { file_id: id, version } }),
      );
      this.render(c);
    } catch (x) {
      (this.querySelector("#vw-h") as HTMLElement).textContent = "Could not open this item";
      const msg = viewerErr(x);
      (this.querySelector("#vw-status") as HTMLElement).textContent = msg;
      (this.querySelector("#vw-body") as HTMLElement).replaceChildren();
      toast("error", msg);
    }
  }

  disconnectedCallback() {
    this.unlisten?.();
  }

  private render(c: OpenedContent) {
    (this.querySelector("#vw-h") as HTMLElement).textContent = c.title || "(untitled)";
    const body = this.querySelector("#vw-body") as HTMLElement;
    body.replaceChildren();
    if (c.file_type === "video") {
      // Video is backed by the sandboxed worker (Gate 4.x) + the <video-player>
      // chrome (Gate 5.3): mount the player on the REQUESTED id (never the served
      // manifest's) so it opens exactly the item the user navigated to.
      const vp = document.createElement("video-player");
      vp.setAttribute("file-id", this.reqId);
      (vp as unknown as VideoPlayer).fileId = this.reqId;
      body.appendChild(vp);
    } else if (c.image_png_b64) {
      const img = document.createElement("img");
      img.src = `data:image/png;base64,${c.image_png_b64}`;
      img.alt = c.title || "Image";
      body.appendChild(img);
    } else if (c.blog_text !== null) {
      const pre = document.createElement("pre");
      pre.textContent = c.blog_text; // textContent: blog text is never HTML
      body.appendChild(pre);
    }
    const meta = this.querySelector("#vw-meta") as HTMLElement;
    meta.replaceChildren();
    const add = (dt: string, dd: string) => {
      const d1 = document.createElement("dt");
      d1.textContent = dt;
      const d2 = document.createElement("dd");
      d2.textContent = dd;
      meta.append(d1, d2);
    };
    add("Verified author", c.author_fp);
    add("Version", String(c.version));
    if (c.tags.length) add("Tags", c.tags.map((t) => `#${t}`).join(" "));
    if (!c.recovery_ok) add("Note", "No recovery grant present.");
  }
}

function viewerErr(x: unknown): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return "This item could not be opened.";
}

customElements.define("media-viewer", MediaViewer);
