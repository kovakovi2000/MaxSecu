import { call } from "../core/rpc.ts";
import { serial, serialPriority } from "../core/serial.ts";
import { toast } from "../core/toast.ts";
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
export class BundleScreen extends HTMLElement {
  private view: BundleView | null = null;
  private mode: BundleViewMode = readBundleViewMode();

  connectedCallback() {
    const params = new URLSearchParams(location.hash.split("?")[1] ?? "");
    const id = params.get("id") ?? "";

    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="bd-h">
        <a href="#/feed" class="back-link">← Back to feed</a>
        <div class="bundle-head">
          <h1 id="bd-h">Bundle</h1>
          <p id="bd-status" role="status" aria-live="polite">Loading…</p>
          <div class="bundle-toggle" role="group" aria-label="View mode">
            <button id="bd-gallery" type="button" class="bundle-mode">Gallery</button>
            <button id="bd-stacked" type="button" class="bundle-mode">Stacked</button>
          </div>
          <button id="bd-download-all" type="button" class="secondary" disabled>Download all</button>
        </div>
        <div id="bd-members"></div>
      </main>`;
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
  // members (no re-fetch — mode is a pure presentation concern).
  private setMode(mode: BundleViewMode) {
    if (mode === this.mode) return;
    this.mode = mode;
    writeBundleViewMode(mode);
    this.syncToggle();
    this.render();
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

    let folder: string | null;
    try {
      folder = await call<string | null>("pick_folder");
    } catch (x) {
      toast("error", bundleErr(x));
      return;
    }
    if (folder === null) return; // user cancelled the folder dialog

    const btn = this.querySelector("#bd-download-all") as HTMLButtonElement;
    btn.disabled = true;
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
    btn.disabled = false;
    toast(ok === total ? "success" : "info", `Downloaded ${ok} of ${total}.`);
  }

  private render() {
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

function bundleErr(x: unknown): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return "This bundle could not be opened.";
}

customElements.define("bundle-screen", BundleScreen);
