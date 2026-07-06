import { call, on } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { runViewerOpen } from "../core/viewer-open.ts";
import { needsConfirm, confirmModal } from "../core/confirm.ts";
import { settingsStore } from "../core/settings.ts";
import type { OpenedContent, FetchMsg } from "../core/types.ts";
import "./progress-meter.ts";
import "./skeleton-card.ts";
import "./video-player.ts";
import type { VideoPlayer } from "./video-player.ts";
import "./share-dialog.ts";
import type { ShareDialog } from "./share-dialog.ts";
import { toast } from "../core/toast.ts";
import { downloadPost } from "../core/download.ts";

// Viewer (spec §5): renders one decrypted post. Image → data: URL <img>; blog →
// textContent (NEVER innerHTML). Subscribes to EVT_FETCH for live status. The
// decrypted content shown is the product; no keys cross the boundary. open_content
// does a connect-lock-bound reauth (single holder via try_lock), so it is routed
// through the shared serial() FIFO. This serializes concurrent opens — e.g. the
// Stacked bundle view mounting several embedded viewers at once — which would
// otherwise race the connect lock and fail with "busy" (only the first loading).
export class MediaViewer extends HTMLElement {
  private cleanup: (() => void) | null = null;
  private reqId = "";
  // The opened content (for the Download button), set on a successful open.
  private opened: OpenedContent | null = null;
  // Whether this viewer is an embedded (Stacked bundle-member) instance. The
  // owner-only Delete is shown ONLY in the routed viewer — deleting a lone member
  // would break the bundle, so embedded viewers never surface Delete.
  private embedded = false;

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
    this.embedded = embedded;
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
          <a id="vw-back" href="#/feed" class="back-link">← Back to feed</a>
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
      const back = backTarget(new URLSearchParams(location.hash.split("?")[1] ?? ""));
      const backLink = this.querySelector("#vw-back") as HTMLAnchorElement;
      backLink.href = back.href;
      backLink.textContent = back.label;
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
        serial(() =>
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
    this.opened = c;

    // A Download button on ANY successful open (routed and embedded — the head
    // markup is shared). Verify+decrypt+write happens in the TCB (download_content);
    // built via createElement so no dynamic data is templated into innerHTML.
    if (!this.querySelector("#vw-dl-btn")) {
      const dlBtn = document.createElement("button");
      dlBtn.id = "vw-dl-btn";
      dlBtn.type = "button";
      dlBtn.className = "secondary";
      dlBtn.textContent = "Download";
      dlBtn.addEventListener("click", () => {
        if (this.opened) void downloadPost(this.reqId, this.opened.file_type, this.opened.title);
      });
      (this.querySelector("#vw-share-btn") as HTMLElement).insertAdjacentElement("afterend", dlBtn);
    }

    // Owner-only permanent Delete (bundles Task 6.2). Shown ONLY in the routed
    // viewer (never embedded — a lone member delete would break its bundle) and
    // only when THIS user authored the item (`c.mine`). Built via createElement so
    // no dynamic data is templated into innerHTML.
    if (c.mine && !this.embedded && !this.querySelector("#vw-del-btn")) {
      const delBtn = document.createElement("button");
      delBtn.id = "vw-del-btn";
      delBtn.type = "button";
      delBtn.className = "danger";
      delBtn.textContent = "Delete";
      delBtn.addEventListener("click", () => void this.onDelete(delBtn));
      (this.querySelector("#vw-dl-btn") as HTMLElement).insertAdjacentElement("afterend", delBtn);
    }

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
      // Embedded (Stacked bundle) viewers must not let their player steal focus.
      if (this.embedded) vp.setAttribute("embedded", "");
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

  // Owner-only permanent delete. Honors the `confirm_destructive` behavior
  // setting: when on (the default-safe path), a confirm modal surfaces the
  // PERMANENT + already-downloaded-copies caveat first; when the user has opted
  // out of prompts, the delete proceeds directly. On success → toast + navigate
  // to #/feed (forces the feed to re-mount + refresh, dropping the deleted item);
  // on error → error toast (the backend error is already sanitized — no oracle).
  private async onDelete(btn: HTMLButtonElement) {
    const confirmDestructive = settingsStore.get().behavior.confirm_destructive;
    if (needsConfirm(confirmDestructive)) {
      const ok = await confirmModal({
        title: "Delete this post?",
        message:
          "Delete this permanently? This can't be undone. Copies others have " +
          "already downloaded can't be reached.",
      });
      if (!ok) return;
    }
    btn.disabled = true;
    try {
      await serial(() => call<void>("delete_content", { req: { file_id: this.reqId } }));
      toast("success", "Post deleted.");
      // Navigate to the feed; the router re-mounts <feed-screen>, refreshing the
      // listing so the deleted item is gone.
      location.hash = "#/feed";
    } catch (x) {
      btn.disabled = false;
      toast("error", viewerErr(x));
    }
  }
}

function backTarget(params: URLSearchParams): { href: string; label: string } {
  const from = params.get("from");
  if (from === "mine") return { href: "#/mine", label: "← Back to My Content" };
  if (from === "bundle") {
    const bundle = params.get("bundle") ?? "";
    const href = bundle ? `#/bundle?id=${encodeURIComponent(bundle)}` : "#/feed";
    return { href, label: "← Back to bundle" };
  }
  return { href: "#/feed", label: "← Back to feed" };
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
