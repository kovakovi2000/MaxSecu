import { call, on } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { decodePool } from "../core/pool.ts";
import { toast } from "../core/toast.ts";
import { renderPager, type PagerFocus } from "../core/pager.ts";
import { clampPage, offsetFor, pageCount, shouldShowPager, showingLabel } from "../core/paging.ts";
import type { FeedEntry, FeedFilter, FeedPage, FeedSort, SearchHit, UploadMsg } from "../core/types.ts";
import "./media-card.ts";
import "./state-badge.ts";
import "./skeleton-card.ts";

// Feed / Library (spec §5). Lists accessible content; filter by type, sort, search
// titles+tags (client-side over the local index). Each item is a <media-card> that
// decrypts itself. Empty/loading/error are first-class.
//
// Two routes mount this: `<feed-screen>` (#/feed, everything) and
// `<feed-screen mine>` (#/mine, owner-only). #/mine is now a real SERVER-SIDE
// owner-filtered listing (`owner_me: true` → `owner=me`), not a per-card
// client-side cull.
//
// PAGING (F3). Numbered pages, page size PAGE_SIZE, driven by the server's
// `offset` + `total`. Each page REPLACES the grid (renderEntries still
// replaceChildren()s) — it never appends. Changing the type filter or the sort
// resets to page 1.
//
// THE OLD-SERVER RULE. A response whose `total` is null came from a server that
// does not paginate: it ignored `offset`/`cursor`/`sort`/`owner` and returned
// page 1. In that case this screen renders NO pager, never sends offset > 0, and
// falls back to today's exact behaviour — including re-applying the owner cull
// per card (`mine-only`), which is the only thing that keeps #/mine honest there.
//
// Module-level retained view-state so returning to the feed restores instantly
// (spec §8) instead of visibly rebuilding. Keyed by mine-vs-all so the two routes
// don't clobber each other. It carries the current page, so returning to the feed
// lands the user back where they left, not on page 1.
const PAGE_SIZE = 50;

interface FeedView {
  entries: FeedEntry[];
  filter: FeedFilter;
  sort: FeedSort;
  page: number;
  // null ⇒ the server does not paginate (see THE OLD-SERVER RULE above).
  total: number | null;
  scrollY: number;
}
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
  private page = 0;
  // null until the first response lands; stays null against a server that does
  // not paginate.
  private total: number | null = null;
  // Set for exactly one load when a load has already been retried (out-of-range
  // page, or an old server that ignored our offset), so a bad response can never
  // drive an unbounded reload loop.
  private retried = false;
  private pagerFocus: PagerFocus | undefined;

  private get key(): "all" | "mine" { return this.hasAttribute("mine") ? "mine" : "all"; }

  connectedCallback() {
    this.mineOnly = this.hasAttribute("mine");
    const r = retained[this.key];
    if (r) { this.filter = r.filter; this.sort = r.sort; this.page = r.page; this.total = r.total; }

    // NOTE: the innerHTML template below is FULLY STATIC — no `${}` interpolation.
    // The one dynamic bit (heading text: "Feed" vs "My Content") is applied AFTER
    // assignment via textContent. This is deliberate: the a11y XSS lint flags ANY
    // `${` inside an innerHTML template, and a route flag templated raw would still
    // trip it. Keep it static. (The old "Only my uploads" checkbox was removed —
    // the My Content nav tab (#/mine → the `mine` attribute) is the owner-only view.)
    // #fd-pager is the numbered-page control's host: static and `hidden` by
    // default so a non-paginating server leaves the screen exactly as it is today;
    // its buttons are built by core/pager.ts and wired with addEventListener.
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
        <nav id="fd-pager" class="pager" aria-label="Feed pages" hidden></nav>
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
      // A different filter or sort is a different result set — the old page
      // number means nothing in it. Reset to page 1.
      this.page = 0;
      this.pagerFocus = undefined;
      this.load();
    });
    const q = form.querySelector('input[name="q"]') as HTMLInputElement;
    q.addEventListener("input", () => this.runSearch(q.value));

    // Manual refresh: clear any search box and force a fresh server listing,
    // bypassing the retained (cached) view so newly-posted items appear. The page
    // number is KEPT (a refresh is not a filter change); if the listing shrank
    // under it, the out-of-range guard in load() clamps and reloads once.
    (this.querySelector("#refresh") as HTMLButtonElement).addEventListener("click", () => {
      q.value = "";
      retained[this.key] = null;
      this.pagerFocus = undefined;
      this.load();
    });

    if (r && r.entries.length) {
      this.renderEntries(r.entries);
      this.renderStatusAndPager(r.entries.length);
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
    // `this.page` is only ever > 0 while a pager is on screen, and a pager is
    // only ever on screen when the server reported a `total` — so this can never
    // send offset > 0 to a server that does not paginate. The post-response guard
    // below is the belt-and-braces for the downgrade case (a paginating server
    // replaced by an old one between two loads).
    const requested = this.page;
    try {
      const page = await serial(() => call<FeedPage>("list_feed", {
        req: {
          filter: this.filter,
          sort: this.sort,
          limit: PAGE_SIZE,
          offset: offsetFor(requested, PAGE_SIZE),
          owner_me: this.mineOnly,
        },
      }));
      this.total = page.total;

      // Old server (no `total`) that we nevertheless asked for a later page:
      // whatever came back is page 1, not the page we asked for. Snap to page 1
      // and reload ONCE so the screen and the data agree.
      if (page.total === null && offsetFor(requested, PAGE_SIZE) > 0 && !this.retried) {
        this.retried = true;
        this.page = 0;
        this.load();
        return;
      }
      // Out-of-range page against a paginating server (the listing shrank under
      // us): clamp and reload ONCE.
      if (page.total !== null) {
        const count = pageCount(page.total, PAGE_SIZE);
        if (this.page > 0 && this.page >= count && !this.retried) {
          this.retried = true;
          this.page = clampPage(this.page, count);
          this.load();
          return;
        }
      }
      this.retried = false;
      this.page = page.total === null ? 0 : this.page;

      retained[this.key] = {
        entries: page.entries,
        filter: this.filter,
        sort: this.sort,
        page: this.page,
        total: this.total,
        scrollY: 0,
      };
      this.renderEntries(page.entries);
      this.renderStatusAndPager(page.entries.length);
    } catch (x) {
      (this.querySelector("#grid") as HTMLElement).replaceChildren();
      (this.querySelector("#fd-pager") as HTMLElement).hidden = true;
      status.textContent = errMsg(x, "Could not load the feed.");
      toast("error", errMsg(x, "Could not load the feed."));
    }
  }

  // The status line + the numbered pager, both derived from `this.total`.
  //  * total === null (old server) → today's exact line, and NO pager.
  //  * total !== null → the honest "Showing X-Y of N." over the whole listing,
  //    which is what makes the #/mine count stop lying.
  private renderStatusAndPager(shown: number) {
    const status = this.querySelector("#fd-status") as HTMLElement;
    const nav = this.querySelector("#fd-pager") as HTMLElement;
    if (this.total === null) {
      status.textContent = shown === 0 ? "No content yet." : `${shown} item(s).`;
      nav.hidden = true;
      nav.replaceChildren();
      return;
    }
    status.textContent = showingLabel(this.page, PAGE_SIZE, this.total);
    if (!shouldShowPager(this.total, PAGE_SIZE)) {
      nav.hidden = true;
      nav.replaceChildren();
      return;
    }
    const focus = this.pagerFocus;
    this.pagerFocus = undefined;
    renderPager(nav, {
      page: this.page,
      count: pageCount(this.total, PAGE_SIZE),
      label: "Feed pages",
      focus,
      onGo: (p, from) => {
        const count = pageCount(this.total ?? 0, PAGE_SIZE);
        const next = clampPage(p, count);
        if (next === this.page) return;
        this.page = next;
        this.pagerFocus = from;
        window.scrollTo(0, 0);
        this.load();
      },
    });
  }

  private renderEntries(entries: FeedEntry[]) {
    const grid = this.querySelector("#grid") as HTMLElement;
    // Numbered pages REPLACE the grid — they never append.
    grid.replaceChildren();
    for (const e of entries) {
      const card = document.createElement("media-card");
      card.setAttribute("file-id", e.file_id);
      card.setAttribute("file-type", e.file_type);
      card.setAttribute("version", String(e.version));
      card.setAttribute("role", "listitem");
      card.setAttribute("return-route", this.mineOnly ? "mine" : "feed");
      // `mine-only` makes <media-card> remove ITSELF after decrypt when the card
      // is not the caller's (media-card.ts). On a paginating server the owner
      // filter already ran SERVER-side (`owner=me`), so wiring it here would be
      // dead code that could only ever silently drop a row the server said is
      // ours — and it would contradict the honest `total`. It is therefore set
      // ONLY on the legacy path (total === null), where the server ignored
      // `owner=me` and this cull is the sole thing keeping #/mine correct.
      if (this.mineOnly && this.total === null) card.setAttribute("mine-only", "");
      grid.appendChild(card);
    }
  }

  // Local index search (D-F). It bypasses the server listing entirely — the hits
  // come from the on-disk index, unpaginated and unordered by `updated_at` — so
  // the numbered pager is hidden for as long as results are shown. Clearing the
  // box calls load(), which restores the current page AND its pager.
  private async runSearch(query: string) {
    const status = this.querySelector("#fd-status")!;
    const nav = this.querySelector("#fd-pager") as HTMLElement;
    if (query.trim() === "") { this.load(); return; }
    nav.hidden = true;
    nav.replaceChildren();
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
        // The local index is not owner-scoped, so on #/mine the per-card cull is
        // still what makes search results owner-only — regardless of server age.
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
