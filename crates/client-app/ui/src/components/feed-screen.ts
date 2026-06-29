import { call } from "../core/rpc.ts";
import type { FeedEntry, FeedFilter, FeedSort, SearchHit } from "../core/types.ts";
import "./media-card.ts";
import "./state-badge.ts";

// Feed / Library (spec §5). Lists accessible content; filter by type, sort, search
// titles+tags (client-side over the local index), and "only my uploads". Each item
// is a <media-card> that decrypts itself. Empty/loading/error are first-class.
export class FeedScreen extends HTMLElement {
  private filter: FeedFilter = "all";
  private sort: FeedSort = "newest-first";
  private mineOnly = false;

  connectedCallback() {
    this.innerHTML = `
      <main id="main" tabindex="-1" aria-labelledby="fd-h">
        <h1 id="fd-h">Feed</h1>
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
          <label><input type="checkbox" name="mine" /> Only my uploads</label>
        </form>
        <p id="fd-status" role="status" aria-live="polite">Loading…</p>
        <div id="grid" role="list"></div>
      </main>`;
    (this.querySelector("#main") as HTMLElement).focus();
    const form = this.querySelector("#controls") as HTMLFormElement;
    form.addEventListener("change", (e) => {
      if ((e.target as HTMLElement)?.getAttribute("name") === "q") return;
      const d = new FormData(form);
      this.filter = (d.get("type") as FeedFilter) ?? "all";
      this.sort = (d.get("sort") as FeedSort) ?? "newest-first";
      this.mineOnly = !!d.get("mine");
      this.load();
    });
    const q = form.querySelector('input[name="q"]') as HTMLInputElement;
    q.addEventListener("input", () => this.runSearch(q.value));
    this.load();
  }

  private async load() {
    const status = this.querySelector("#fd-status")!;
    const grid = this.querySelector("#grid") as HTMLElement;
    status.textContent = "Loading…";
    try {
      const entries = await call<FeedEntry[]>("list_feed", {
        req: { filter: this.filter, sort: this.sort },
      });
      grid.replaceChildren();
      if (entries.length === 0) {
        status.textContent = "No content yet.";
        return;
      }
      status.textContent = `${entries.length} item(s).`;
      for (const e of entries) {
        const card = document.createElement("media-card");
        card.setAttribute("file-id", e.file_id);
        card.setAttribute("file-type", e.file_type);
        card.setAttribute("role", "listitem");
        if (this.mineOnly) card.setAttribute("mine-only", "");
        grid.appendChild(card);
      }
    } catch (x) {
      status.textContent = errMsg(x, "Could not load the feed.");
    }
  }

  private async runSearch(query: string) {
    const status = this.querySelector("#fd-status")!;
    if (query.trim() === "") {
      this.load();
      return;
    }
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
