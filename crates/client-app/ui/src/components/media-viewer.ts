import { call, on } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { runViewerOpen } from "../core/viewer-open.ts";
import { needsConfirm, confirmModal } from "../core/confirm.ts";
import { settingsStore } from "../core/settings.ts";
import { cardHref } from "../core/card-view.ts";
// The bundle screen owns the retained, SIGNATURE-VERIFIED member order (see the
// "Retained bundle state" block there) — this is where next/previous gets its
// order from, and the only place it may come from.
//
// This is a module cycle (bundle-screen.ts imports this file for the embedded
// <media-viewer> element). It is init-safe in both load orders: neither module
// touches the other's bindings at module-evaluation time, only inside methods.
import {
  bundleNeighbours,
  memberVersion,
  rememberBundlePageFor,
  rememberMemberVersion,
} from "./bundle-screen.ts";
import type { BundleMemberView, OpenedContent, FetchMsg } from "../core/types.ts";
import "./progress-meter.ts";
import "./skeleton-card.ts";
import "./video-player.ts";
import type { VideoPlayer } from "./video-player.ts";
import "./share-dialog.ts";
import type { ShareDialog } from "./share-dialog.ts";
import { toast } from "../core/toast.ts";
import { downloadPost } from "../core/download.ts";
import { getPrincipalKind } from "../core/session.ts";

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
  // The bundle this item is being viewed as a member OF, or "" when it is not.
  // Set from `from=bundle&bundle=…` (routed) or the `bundle-id` attribute
  // (embedded). It gates next/previous and is the key under which a verified
  // version is remembered for later opens.
  private bundleId = "";

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
      // An embedded (Stacked bundle-member) viewer is handed the member's version
      // whenever the host knows one, so the open can short-circuit on the content
      // cache BEFORE any network or reauth. Absent ⇒ exactly today's behaviour.
      version = parseVersion(this.getAttribute("version"));
      this.bundleId = this.getAttribute("bundle-id") ?? "";
    } else {
      const params = new URLSearchParams(location.hash.split("?")[1] ?? "");
      id = params.get("id") ?? "";
      version = parseVersion(params.get("v"));
      if (params.get("from") === "bundle") this.bundleId = params.get("bundle") ?? "";
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
          <nav id="vw-bundle-nav" class="viewer-bundle-nav" aria-label="Bundle navigation" hidden>
            <button id="vw-prev" type="button" class="secondary" aria-label="Previous item">← Previous</button>
            <span id="vw-pos" class="viewer-bundle-pos"></span>
            <button id="vw-next" type="button" class="secondary" aria-label="Next item">Next →</button>
          </nav>
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
      // Next/Previous over the bundle's members, wired BEFORE the open so the walk
      // is usable while the item is still decrypting.
      if (this.bundleId !== "") this.renderBundleNav(this.bundleId, id);
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

  // Next / Previous across the bundle this item belongs to, so a member opened
  // from a gallery can be walked without bouncing back to the gallery each time.
  //
  // ORDER: strictly the retained, SIGNATURE-VERIFIED member list that open_bundle
  // returned (see bundle-screen.ts). It is never re-derived from a feed listing,
  // the local index, or the DOM — commands/bundle.rs is explicit that members must
  // never be read from a server-served listing, and that rule does not stop at the
  // seam. When this session has not opened that bundle (a reload, or a typed
  // deep-link straight to #/viewer?from=bundle) there IS no verified order, so the
  // controls stay hidden rather than offering a guessed one.
  //
  // KEYBOARD: these are real <button>s, so Enter/Space work by default — which is
  // the whole of what this viewer binds. Deliberately NO global Arrow-key binding:
  // an opened video mounts <video-player>, whose Media Chrome hotkeys already own
  // ArrowLeft/ArrowRight for seeking, and stealing those would break playback.
  private renderBundleNav(bundleId: string, fileId: string) {
    const nav = this.querySelector("#vw-bundle-nav") as HTMLElement | null;
    if (nav === null) return;
    const around = bundleNeighbours(bundleId, fileId);
    if (around === null || around.total <= 1) return;
    // Keep the gallery's retained page in step with the walk, so "Back to bundle"
    // lands on the page CONTAINING this item even after crossing a page boundary.
    rememberBundlePageFor(bundleId, fileId);
    (this.querySelector("#vw-pos") as HTMLElement).textContent =
      `Item ${around.index + 1} of ${around.total}`;
    const prev = this.querySelector("#vw-prev") as HTMLButtonElement;
    const next = this.querySelector("#vw-next") as HTMLButtonElement;
    // Disabled at the ends — an enabled control that does nothing when pressed is
    // worse than one that says it is unavailable.
    prev.disabled = around.prev === null;
    next.disabled = around.next === null;
    prev.addEventListener("click", () => this.goToMember(bundleId, around.prev));
    next.addEventListener("click", () => this.goToMember(bundleId, around.next));
    nav.hidden = false;
  }

  // Walk to a neighbour by ROUTING to it, exactly like every other navigation in
  // the app, so the back/forward stack, the back-link and the address bar all stay
  // honest. `cardHref` carries the member's version when one is known, which is
  // what lets the re-open hit the content cache instead of re-running the whole
  // verify ladder (and a nested bundle member correctly routes to #/bundle).
  private goToMember(bundleId: string, m: BundleMemberView | null) {
    if (m === null) return;
    location.hash = cardHref(m.file_type, m.file_id, memberVersion(bundleId, m), { bundleId });
  }

  private render(c: OpenedContent) {
    (this.querySelector("#vw-h") as HTMLElement).textContent = c.title || "(untitled)";
    // Hidden for a RECOVERY principal: `reshare_file` refuses one outright
    // (`recovery_share_unsupported`), so offering the button would be a guaranteed
    // dead end. This is a CLOSED decision (2026-08-02), not a pending feature —
    // restoring someone's access is done via the offline recovery-key ceremony
    // (DESIGN §12.7), never from a live recovery session.
    (this.querySelector("#vw-share-btn") as HTMLButtonElement).hidden =
      !c.can_share || getPrincipalKind() === "recovery";
    this.opened = c;

    // Remember the VERIFIED version of this bundle member. The signed BundleBody
    // carries only (file_id, file_type) — no versions — so this successful open is
    // the cheapest place the client ever learns one, and knowing it is what lets
    // the next re-open (the next/previous walk, or returning to the item) skip the
    // network entirely on the content cache. A no-op outside a bundle.
    if (this.bundleId !== "") rememberMemberVersion(this.bundleId, this.reqId, c.version);

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

// A version is only worth sending when it is a REAL one. Versions start at 1 in
// Rust, and `open_content` treats a supplied version as authoritative: it tries
// the content cache on it BEFORE the network and then SKIPS its second,
// post-fetch cache check (that one is gated on the version being absent). So a 0,
// a NaN or an empty string must all become "absent" — sending one would cost the
// open both cache chances instead of buying it one.
function parseVersion(raw: string | null): number | undefined {
  if (raw === null || raw.trim() === "") return undefined;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : undefined;
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
