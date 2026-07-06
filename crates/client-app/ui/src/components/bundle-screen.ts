import { call } from "../core/rpc.ts";
import { serial, serialPriority } from "../core/serial.ts";
import { toast } from "../core/toast.ts";
import { needsConfirm, confirmModal } from "../core/confirm.ts";
import { settingsStore } from "../core/settings.ts";
import { downloadName, dedupeName } from "../core/download-name.ts";
import {
  readBundleViewMode,
  writeBundleViewMode,
  type BundleViewMode,
} from "../core/bundle-view.ts";
import type { BundleView } from "../core/types.ts";
import "./media-card.ts";
import "./media-viewer.ts";
import "./skeleton-card.ts";
import "./share-dialog.ts";
import type { ShareDialog } from "./share-dialog.ts";

// Bundle screen (bundles feature, Task 3.3): opens one bundle (#/bundle?id=<hex>)
// and shows its members two ways (design §7):
//  • Gallery — a grid of <media-card>s. Each decrypts itself (title/thumbnail)
//    via decrypt_card and links to its own viewer (decrypt-on-tap).
//  • Stacked — the members rendered inline, FULLY OPENED, in order: one embedded
//    <media-viewer file-id="…" embedded> per member (same content the routed
//    viewer shows — image/blog/video). The bundle screen owns the single #main
//    landmark; the embedded viewers emit none.
// The chosen mode is remembered across opens (localStorage, default Gallery).
// open_bundle is routed through the priority serial queue (the backend re-auths
// per call and cannot run those concurrently with card/member decrypts).
//
// XSS note: the innerHTML skeleton below is FULLY STATIC. All dynamic content
// (member cards, status text) is built via createElement/textContent — never
// interpolated into innerHTML (the a11y lint flags any `${` in an innerHTML
// template that isn't the esc() helper).
// Debounce window for the Gallery⇄Stacked re-render. Long enough to collapse a
// burst of toggles, short enough to feel immediate.
const MODE_DEBOUNCE_MS = 150;

export class BundleScreen extends HTMLElement {
  private view: BundleView | null = null;
  private mode: BundleViewMode = readBundleViewMode();
  // Render-generation guard (Issue 1): a monotonically increasing token. A
  // debounced setMode schedules a re-render tagged with the current generation;
  // if a newer toggle bumps the generation first, the stale scheduled render is
  // dropped. This shrinks the window in which rapid toggles fan out overlapping
  // member loads that would contend the connect lock.
  private renderGen = 0;
  private modeTimer: ReturnType<typeof setTimeout> | null = null;

  connectedCallback() {
    const params = new URLSearchParams(location.hash.split("?")[1] ?? "");
    const id = params.get("id") ?? "";
    const back = backTarget(params);

    this.innerHTML = `
      <main id="main" class="bundle-main" tabindex="-1" aria-labelledby="bd-h">
        <a id="bd-back" href="#/feed" class="back-link">← Back to feed</a>
        <div class="bundle-head">
          <div class="screen-title">
            <p class="eyebrow">bundle viewer</p>
            <h1 id="bd-h">Bundle</h1>
            <p id="bd-status" role="status" aria-live="polite">Loading…</p>
          </div>
          <div class="bundle-toolbar" aria-label="Bundle actions">
            <div class="bundle-toggle" role="group" aria-label="View mode">
              <button id="bd-gallery" type="button" class="bundle-mode">Gallery</button>
              <button id="bd-stacked" type="button" class="bundle-mode">Stacked</button>
            </div>
            <button id="bd-download-all" type="button" class="secondary" disabled>Download all</button>
            <button id="bd-share" type="button" class="secondary" hidden>Share…</button>
            <button id="bd-delete" type="button" class="danger" hidden>Delete bundle</button>
          </div>
        </div>
        <div id="bd-members"></div>
      </main>
      <share-dialog id="bd-share-dialog"></share-dialog>`;
    const backLink = this.querySelector("#bd-back") as HTMLAnchorElement;
    backLink.href = back.href;
    backLink.textContent = back.label;
    (this.querySelector("#main") as HTMLElement).focus();

    this.syncToggle();
    (this.querySelector("#bd-gallery") as HTMLButtonElement).addEventListener("click", () =>
      this.setMode("gallery"),
    );
    (this.querySelector("#bd-stacked") as HTMLButtonElement).addEventListener("click", () =>
      this.setMode("stacked"),
    );
    (this.querySelector("#bd-download-all") as HTMLButtonElement).addEventListener("click", () =>
      void this.downloadAll(),
    );
    (this.querySelector("#bd-delete") as HTMLButtonElement).addEventListener("click", () =>
      void this.onDelete(),
    );
    // Share… (bundles Task 8.1): any wrap-holder who opened the bundle may share
    // it. The dialog is told the target is a "bundle" so Share fans out over the
    // bundle AND every member as a unit (reshare_bundle).
    const shareBtn = this.querySelector("#bd-share") as HTMLButtonElement;
    shareBtn.addEventListener("click", () => {
      if (!this.view) return;
      const dialog = this.querySelector("#bd-share-dialog") as ShareDialog;
      dialog.openFor(this.view.file_id, shareBtn, "bundle");
    });

    // Skeleton while the bundle resolves.
    const members = this.querySelector("#bd-members") as HTMLElement;
    members.appendChild(document.createElement("skeleton-card"));

    if (id === "") {
      this.fail("No bundle id was given.");
      return;
    }

    void this.load(id);
  }

  private async load(id: string) {
    try {
      const view = await serialPriority(() =>
        call<BundleView>("open_bundle", { req: { file_id: id } }),
      );
      this.view = view;
      const n = view.members.length;
      (this.querySelector("#bd-status") as HTMLElement).textContent =
        n === 0 ? "This bundle is empty." : `${n} item${n === 1 ? "" : "s"}.`;
      // Download-all only makes sense once there is at least one member.
      (this.querySelector("#bd-download-all") as HTMLButtonElement).disabled = n === 0;
      // Owner-only "Delete bundle" (bundles Task 6.2): shown only to the author.
      (this.querySelector("#bd-delete") as HTMLButtonElement).hidden = !view.mine;
      // Share… is available to ANY wrap-holder who could open the bundle (not
      // ownership-gated) — mirrors the viewer's can_share affordance.
      (this.querySelector("#bd-share") as HTMLButtonElement).hidden = false;
      this.render();
    } catch (x) {
      this.fail(bundleErr(x));
    }
  }

  private fail(msg: string) {
    this.view = null;
    (this.querySelector("#bd-status") as HTMLElement).textContent = msg;
    (this.querySelector("#bd-members") as HTMLElement).replaceChildren();
    toast("error", msg);
  }

  // Switch view mode: persist the choice and re-render the already-fetched
  // members (no re-fetch — mode is a pure presentation concern). The toggle's
  // visual state flips immediately for feedback; the expensive member re-render
  // is debounced and generation-guarded so a burst of toggles collapses to the
  // final mode and never leaves a superseded render running.
  private setMode(mode: BundleViewMode) {
    if (mode === this.mode) return;
    this.mode = mode;
    writeBundleViewMode(mode);
    this.syncToggle();
    const gen = ++this.renderGen;
    if (this.modeTimer !== null) clearTimeout(this.modeTimer);
    this.modeTimer = setTimeout(() => {
      this.modeTimer = null;
      if (gen !== this.renderGen) return; // superseded by a newer toggle
      this.render();
    }, MODE_DEBOUNCE_MS);
  }

  disconnectedCallback() {
    // Drop any pending debounced re-render so it can't fire into a torn-down view.
    if (this.modeTimer !== null) {
      clearTimeout(this.modeTimer);
      this.modeTimer = null;
    }
  }

  private syncToggle() {
    const gallery = this.querySelector("#bd-gallery") as HTMLButtonElement;
    const stacked = this.querySelector("#bd-stacked") as HTMLButtonElement;
    gallery.setAttribute("aria-pressed", String(this.mode === "gallery"));
    stacked.setAttribute("aria-pressed", String(this.mode === "stacked"));
    gallery.classList.toggle("active", this.mode === "gallery");
    stacked.classList.toggle("active", this.mode === "stacked");
  }

  // Download-all (design §7): pick ONE destination folder, then verify+decrypt+write
  // every member into it, sequentially — each download_content re-auths and cannot run
  // concurrently, so each is routed through the serial queue. Member titles are empty
  // from open_bundle, so a name is derived per member (`member-<n>.<ext>` by kind) and
  // de-duped so two same-kind members never collide. A member failure is tolerated:
  // the loop continues and the final toast reports how many of M succeeded.
  private async downloadAll() {
    if (!this.view || this.view.members.length === 0) return;
    const members = this.view.members;

    // Disable up front (before the pick_folder await) so a rapid double-click can't
    // open two folder dialogs / two concurrent batches; re-enabled in `finally`.
    const btn = this.querySelector("#bd-download-all") as HTMLButtonElement;
    btn.disabled = true;
    try {
      let folder: string | null;
      try {
        folder = await call<string | null>("pick_folder");
      } catch (x) {
        toast("error", bundleErr(x));
        return;
      }
      if (folder === null) return; // user cancelled the folder dialog

      const sep = folder.includes("\\") ? "\\" : "/";
      const used = new Set<string>();
      const total = members.length;
      let ok = 0;
      for (let i = 0; i < total; i++) {
        const m = members[i];
        const name = dedupeName(downloadName(m.file_type, `member-${i + 1}`), used);
        const savePath = `${folder}${sep}${name}`;
        try {
          await serial(() =>
            call<string>("download_content", { req: { file_id: m.file_id, save_path: savePath } }),
          );
          ok++;
        } catch {
          // Tolerate a single member failure; keep going and report the final tally.
        }
      }
      toast(ok === total ? "success" : "info", `Downloaded ${ok} of ${total}.`);
    } finally {
      btn.disabled = false;
    }
  }

  // Owner-only permanent delete of the WHOLE bundle (server cascades members).
  // Honors `confirm_destructive`: when on (default-safe), a confirm modal surfaces
  // the PERMANENT + member-cascade + already-downloaded-copies caveat first; when
  // the user opted out of prompts, it proceeds directly. On success → toast +
  // navigate to #/feed (re-mounts the feed, dropping the bundle and its members);
  // on error → error toast (backend error already sanitized — no oracle).
  private async onDelete() {
    if (!this.view) return;
    const bundleId = this.view.file_id;
    const confirmDestructive = settingsStore.get().behavior.confirm_destructive;
    if (needsConfirm(confirmDestructive)) {
      const ok = await confirmModal({
        title: "Delete this bundle?",
        message:
          "Delete this bundle and all its members permanently? This can't be " +
          "undone. Copies others have already downloaded can't be reached.",
      });
      if (!ok) return;
    }
    const btn = this.querySelector("#bd-delete") as HTMLButtonElement;
    btn.disabled = true;
    try {
      await serial(() => call<void>("delete_content", { req: { file_id: bundleId } }));
      toast("success", "Bundle deleted.");
      location.hash = "#/feed";
    } catch (x) {
      btn.disabled = false;
      toast("error", bundleErr(x));
    }
  }

  private render() {
    // Any direct render (e.g. the initial load) supersedes a pending debounced one.
    this.renderGen++;
    const container = this.querySelector("#bd-members") as HTMLElement;
    container.replaceChildren();
    if (!this.view) return;
    container.className = this.mode === "gallery" ? "bundle-gallery" : "bundle-stack";
    container.setAttribute("role", "list");

    for (const m of this.view.members) {
      if (this.mode === "gallery") {
        // Gallery: a decrypt-on-tap <media-card> grid cell per member.
        const card = document.createElement("media-card");
        card.setAttribute("file-id", m.file_id);
        card.setAttribute("file-type", m.file_type);
        card.setAttribute("role", "listitem");
        if (this.view) card.setAttribute("return-bundle-id", this.view.file_id);
        container.appendChild(card);
      } else {
        // Stacked: each member is fully opened inline via an embedded
        // <media-viewer> (no landmark/focus chrome), in bundle order.
        const item = document.createElement("section");
        item.className = "bundle-stack-item";
        item.setAttribute("role", "listitem");
        const viewer = document.createElement("media-viewer");
        viewer.setAttribute("file-id", m.file_id);
        viewer.setAttribute("embedded", "");
        item.appendChild(viewer);
        container.appendChild(item);
      }
    }
  }
}

function backTarget(params: URLSearchParams): { href: string; label: string } {
  const from = params.get("from");
  if (from === "mine") return { href: "#/mine", label: "← Back to My Content" };
  return { href: "#/feed", label: "← Back to feed" };
}

function bundleErr(x: unknown): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return "This bundle could not be opened.";
}

customElements.define("bundle-screen", BundleScreen);
