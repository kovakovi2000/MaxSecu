import { call, on } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { decodePool } from "../core/pool.ts";
import { toast } from "../core/toast.ts";
import type { FeedEntry, FeedFilter, FeedSort, SearchHit, UploadMsg } from "../core/types.ts";
import "./media-card.ts";
import "./state-badge.ts";
import "./skeleton-card.ts";

// Feed / Library (spec §5). Lists accessible content; filter by type, sort, search
// titles+tags (client-side over the local index). Each item is a <media-card> that
// decrypts itself. Empty/loading/error are first-class.
//
// Two routes mount this: `<feed-screen>` (#/feed, everything) and
// `<feed-screen mine>` (#/mine, owner-only). In `mine` mode the "Only my uploads"
// toggle is preset and removed (the route already constrains the view).
//
// Module-level retained view-state so returning to the feed restores instantly
// (spec §8) instead of visibly rebuilding. Keyed by mine-vs-all so the two routes
// don't clobber each other.
interface FeedView { entries: FeedEntry[]; filter: FeedFilter; sort: FeedSort; scrollY: number }
const retained: Record<"all" | "mine", FeedView | null> = { all: null, mine: null };

// Invalidate the retained feed when an upload completes, so returning to the
// feed after posting shows the new item instead of a stale cached list.
void on<UploadMsg>("maxsecu://upload-state", (m) => {
  if (m.phase === "done") {
    retained.all = null;
    retained.mine = null;
  }
});

export class FeedScreen extends HTMLElement {
  private filter: FeedFilter = "all";
  private sort: FeedSort = "newest-first";
  private mineOnly = false;

  private get key(): "all" | "mine" { return this.hasAttribute("mine") ? "mine" : "all"; }

  connectedCallback() {
    this.mineOnly = this.hasAttribute("mine");
    const r = retained[this.key];
    if (r) { this.filter = r.filter; this.sort = r.sort; }

    // NOTE: the innerHTML template below is FULLY STATIC — no `${}` interpolation.
    // The one dynamic bit (heading text: "Feed" vs "My Content") is applied AFTER
    // assignment via textContent. This is deliberate: the a11y XSS lint flags ANY
    // `${` inside an innerHTML template, and a route flag templated raw would still
    // trip it. Keep it static. (The old "Only my uploads" checkbox was removed —
    // the My Content nav tab (#/mine → the `mine` attribute) is the owner-only view.)
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="fd-h">
        <h1 id="fd-h"></h1>
        <form id="controls" role="search">
          <label>Search <input name="q" type="search" autocomplete="off"
            aria-describedby="fd-status" /></label>
          <label>Type
            <select name="type">
              <option value="all">All</option>
              <option value="image">Images</option>
              <option value="blog">Blogs</option>
              <option value="video">Video</option>
            </select></label>
          <label>Sort
            <select name="sort">
              <option value="newest-first">Newest first</option>
              <option value="oldest-first">Oldest first</option>
            </select></label>
          <button id="refresh" type="button" class="feed-refresh">Refresh</button>
        </form>
        <p id="fd-status" role="status" aria-live="polite"></p>
        <div id="grid" role="list"></div>
      </main>`;

    (this.querySelector("#fd-h") as HTMLElement).textContent = this.mineOnly ? "My Content" : "Feed";

    (this.querySelector("#main") as HTMLElement).focus();

    (this.querySelector('[name="type"]') as HTMLSelectElement).value = this.filter;
    (this.querySelector('[name="sort"]') as HTMLSelectElement).value = this.sort;

    const form = this.querySelector("#controls") as HTMLFormElement;
    form.addEventListener("change", (e) => {
      if ((e.target as HTMLElement)?.getAttribute("name") === "q") return;
      const d = new FormData(form);
      this.filter = (d.get("type") as FeedFilter) ?? "all";
      this.sort = (d.get("sort") as FeedSort) ?? "newest-first";
      this.load();
    });
    const q = form.querySelector('input[name="q"]') as HTMLInputElement;
    q.addEventListener("input", () => this.runSearch(q.value));

    // Manual refresh: clear any search box and force a fresh server listing,
    // bypassing the retained (cached) view so newly-posted items appear.
    (this.querySelector("#refresh") as HTMLButtonElement).addEventListener("click", () => {
      q.value = "";
      retained[this.key] = null;
      this.load();
    });

    if (r && r.entries.length) {
      this.renderEntries(r.entries);
      (this.querySelector("#fd-status") as HTMLElement).textContent = `${r.entries.length} item(s).`;
      window.requestAnimationFrame(() => window.scrollTo(0, r.scrollY));
    } else {
      this.load();
    }
  }

  disconnectedCallback() {
    // Flush the decodePool's queued card-decode backlog on feed teardown, so a
    // stalled backlog can't wedge the pool and a still-live card gets a benign
    // CancelledError it can retry (see media-card / core/card-retry.ts).
    decodePool.cancelPending();
    const r = retained[this.key];
    if (r) r.scrollY = window.scrollY;
  }

  private showSkeletons(n: number) {
    const grid = this.querySelector("#grid") as HTMLElement;
    grid.replaceChildren();
    for (let i = 0; i < n; i++) grid.appendChild(document.createElement("skeleton-card"));
  }

  private async load() {
    const status = this.querySelector("#fd-status")!;
    status.textContent = "Loading…";
    this.showSkeletons(6);
    try {
      const entries = await serial(() => call<FeedEntry[]>("list_feed", {
        req: { filter: this.filter, sort: this.sort },
      }));
      retained[this.key] = { entries, filter: this.filter, sort: this.sort, scrollY: 0 };
      this.renderEntries(entries);
      status.textContent = entries.length === 0 ? "No content yet." : `${entries.length} item(s).`;
    } catch (x) {
      (this.querySelector("#grid") as HTMLElement).replaceChildren();
      status.textContent = errMsg(x, "Could not load the feed.");
      toast("error", errMsg(x, "Could not load the feed."));
    }
  }

  private renderEntries(entries: FeedEntry[]) {
    const grid = this.querySelector("#grid") as HTMLElement;
    grid.replaceChildren();
    for (const e of entries) {
      const card = document.createElement("media-card");
      card.setAttribute("file-id", e.file_id);
      card.setAttribute("file-type", e.file_type);
      card.setAttribute("version", String(e.version));
      card.setAttribute("role", "listitem");
      card.setAttribute("return-route", this.mineOnly ? "mine" : "feed");
      if (this.mineOnly) card.setAttribute("mine-only", "");
      grid.appendChild(card);
    }
  }

  private async runSearch(query: string) {
    const status = this.querySelector("#fd-status")!;
    if (query.trim() === "") { this.load(); return; }
    try {
      const hits = await call<SearchHit[]>("search_local", { req: { query } });
      const grid = this.querySelector("#grid") as HTMLElement;
      grid.replaceChildren();
      status.textContent = `${hits.length} match(es).`;
      for (const h of hits) {
        const card = document.createElement("media-card");
        card.setAttribute("file-id", h.file_id);
        card.setAttribute("file-type", h.file_type);
        card.setAttribute("role", "listitem");
        card.setAttribute("return-route", this.mineOnly ? "mine" : "feed");
        if (this.mineOnly) card.setAttribute("mine-only", "");
        grid.appendChild(card);
      }
    } catch (x) {
      status.textContent = errMsg(x, "Search failed.");
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

customElements.define("feed-screen", FeedScreen);
