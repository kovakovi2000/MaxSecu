import { call, on } from "../core/rpc.ts";
import { serialPriority } from "../core/serial.ts";
import { runViewerOpen } from "../core/viewer-open.ts";
import type { OpenedContent, FetchMsg } from "../core/types.ts";
import "./progress-meter.ts";
import "./skeleton-card.ts";
import "./video-player.ts";
import type { VideoPlayer } from "./video-player.ts";
import "./share-dialog.ts";
import type { ShareDialog } from "./share-dialog.ts";
import { toast } from "../core/toast.ts";

// Viewer (spec §5): renders one decrypted post. Image → data: URL <img>; blog →
// textContent (NEVER innerHTML). Subscribes to EVT_FETCH for live status. The
// decrypted content shown is the product; no keys cross the boundary. open_content
// is routed through the shared serial() queue (the backend re-auths per call and
// cannot run those concurrently with in-flight card decrypts).
export class MediaViewer extends HTMLElement {
  private cleanup: (() => void) | null = null;
  private reqId = "";

  connectedCallback() {
    // Two mount modes, sharing ALL content rendering (image/blog/video/meta):
    //  • routed (default): the #/viewer?id= screen. Reads the id from the hash and
    //    emits the full landmark chrome (`#main` + tabindex + focus + back-link).
    //  • embedded (`embedded` attr; id from the `file-id` attr): a chrome-less
    //    content block for inline reuse — a Stacked bundle mounts N of these. It
    //    emits NO `#main` landmark and does NOT steal focus, so the host screen
    //    (e.g. <bundle-screen>) keeps the single landmark and there is never a
    //    duplicate `#main` id. The opened content shown is identical in both modes.
    const embedded = this.hasAttribute("embedded");
    const fileIdAttr = this.getAttribute("file-id");
    let id: string;
    let version: number | undefined;
    if (fileIdAttr !== null) {
      id = fileIdAttr;
      version = undefined;
    } else {
      const params = new URLSearchParams(location.hash.split("?")[1] ?? "");
      id = params.get("id") ?? "";
      const vParam = params.get("v");
      version = vParam !== null ? Number(vParam) : undefined;
    }
    this.reqId = id;

    if (embedded) {
      // Chrome-less: no <main>/tabindex landmark, no back-link — the host owns
      // the single landmark. Fully static markup (no `${}` interpolation).
      this.innerHTML = `
        <section class="viewer-frame viewer-embedded" aria-label="Opened post">
          <div class="viewer-head">
            <p class="eyebrow">decrypted payload</p>
            <h1 id="vw-h">Loading…</h1>
            <button id="vw-share-btn" type="button" class="secondary" hidden>Share…</button>
            <p id="vw-status" role="status" aria-live="polite"></p>
            <progress-meter id="vw-meter" hidden></progress-meter>
          </div>
          <div id="vw-body" class="viewer-body"></div>
          <dl id="vw-meta" class="viewer-meta"></dl>
        </section>
        <share-dialog id="vw-share-dialog"></share-dialog>`;
    } else {
      this.innerHTML = `
        <main id="main" class="viewer-main" tabindex="-1" aria-labelledby="vw-h">
          <a href="#/feed" class="back-link">← Back to feed</a>
          <section class="viewer-frame" aria-label="Opened post">
            <div class="viewer-head">
              <p class="eyebrow">decrypted payload</p>
              <h1 id="vw-h">Loading…</h1>
              <button id="vw-share-btn" type="button" class="secondary" hidden>Share…</button>
              <p id="vw-status" role="status" aria-live="polite"></p>
              <progress-meter id="vw-meter" hidden></progress-meter>
            </div>
            <div id="vw-body" class="viewer-body"></div>
            <dl id="vw-meta" class="viewer-meta"></dl>
          </section>
        </main>
        <share-dialog id="vw-share-dialog"></share-dialog>`;
      (this.querySelector("#main") as HTMLElement).focus();
    }

    // The Share… action (T4, D-OQ3): shown on ANY successful open (any current
    // wrap-holder can share — not ownership-gated), per OpenedContent.can_share.
    const shareBtn = this.querySelector("#vw-share-btn") as HTMLButtonElement;
    shareBtn.addEventListener("click", () => {
      const dialog = this.querySelector("#vw-share-dialog") as ShareDialog;
      dialog.openFor(this.reqId, shareBtn);
    });

    const status = this.querySelector("#vw-status")!;
    const meter = this.querySelector("#vw-meter") as HTMLElement;

    (this.querySelector("#vw-body") as HTMLElement).appendChild(
      document.createElement("skeleton-card"),
    );

    // The status subscription is best-effort feedback and is dispatched
    // fire-and-forget — it MUST NOT gate the open. Earlier the viewer `await`ed it
    // before calling open_content, so a non-settling `listen()` left the viewer
    // stuck on "Loading…" forever. `runViewerOpen` owns that contract (unit-tested).
    this.cleanup = runViewerOpen<OpenedContent>({
      subscribe: () =>
        on<FetchMsg>("maxsecu://fetch-state", (m) => {
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
        }),
      open: () =>
        serialPriority(() =>
          call<OpenedContent>("open_content", { req: { file_id: id, version } }),
        ),
      onResult: (c) => this.render(c),
      onError: (x) => {
        (this.querySelector("#vw-h") as HTMLElement).textContent = "Could not open this item";
        const msg = viewerErr(x);
        (this.querySelector("#vw-status") as HTMLElement).textContent = msg;
        (this.querySelector("#vw-body") as HTMLElement).replaceChildren();
        toast("error", msg);
      },
    });
  }

  disconnectedCallback() {
    this.cleanup?.();
  }

  private render(c: OpenedContent) {
    (this.querySelector("#vw-h") as HTMLElement).textContent = c.title || "(untitled)";
    (this.querySelector("#vw-share-btn") as HTMLButtonElement).hidden = !c.can_share;
    const body = this.querySelector("#vw-body") as HTMLElement;
    body.replaceChildren();

    const blogText = readBlogText(c);
    if (c.file_type === "video") {
      // Video is backed by the sandboxed worker (Gate 4.x) + the <video-player>
      // chrome (Gate 5.3): mount the player on the REQUESTED id (never the served
      // manifest's) so it opens exactly the item the user navigated to.
      const vp = document.createElement("video-player");
      vp.setAttribute("file-id", this.reqId);
      (vp as unknown as VideoPlayer).fileId = this.reqId;
      body.appendChild(vp);
    } else if (blogText !== null) {
      const article = document.createElement("article");
      article.className = "blog-content";
      const p = document.createElement("div");
      p.textContent = blogText.trim() === "" ? "This post has no text body." : blogText;
      article.appendChild(p);
      body.appendChild(article);
    } else if (c.image_png_b64) {
      const img = document.createElement("img");
      img.src = `data:image/png;base64,${c.image_png_b64}`;
      img.alt = c.title || "Image";
      body.appendChild(img);
    } else {
      const empty = document.createElement("p");
      empty.className = "empty-content";
      empty.textContent = "No displayable post body was returned for this item.";
      body.appendChild(empty);
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

function readBlogText(c: OpenedContent): string | null {
  if (typeof c.blog_text === "string") return c.blog_text;
  const loose = c as unknown as Record<string, unknown>;
  for (const key of ["text", "content", "body", "post_text"]) {
    const value = loose[key];
    if (typeof value === "string") return value;
  }
  return null;
}

function viewerErr(x: unknown): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return "This item could not be opened.";
}

customElements.define("media-viewer", MediaViewer);
