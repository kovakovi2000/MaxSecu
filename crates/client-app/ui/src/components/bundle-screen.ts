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
import { getPrincipalKind } from "../core/session.ts";
import { renderPager, type PagerFocus } from "../core/pager.ts";
import { clampPage, pageCount, showingLabel } from "../core/paging.ts";
import type { BundleMemberView, BundleView } from "../core/types.ts";
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
//    viewer shows — image/blog/video), mounted LAZILY as it scrolls into view.
//    The bundle screen owns the single #main landmark; the embedded viewers emit
//    none.
// The chosen mode is remembered across opens (settings.json ui.bundle_view via
// the shared settings store, default Gallery).
// open_bundle is routed through the priority serial queue (the backend re-auths
// per call and cannot run those concurrently with card/member decrypts).
//
// XSS note: the innerHTML skeleton below is FULLY STATIC. All dynamic content
// (member cards, status text, the download report) is built via
// createElement/textContent — never interpolated into innerHTML (the a11y lint
// flags any `${` in an innerHTML template that isn't the esc() helper).
// Debounce window for the Gallery⇄Stacked re-render. Long enough to collapse a
// burst of toggles, short enough to feel immediate.
const MODE_DEBOUNCE_MS = 150;

// MEMBER PAGING (F3). The wire format allows 65535 members and there is no cap,
// so a large bundle would otherwise mount thousands of self-decrypting cards (or,
// in Stacked mode, thousands of fully-opened viewers) at once. Members are shown
// MEMBER_PAGE_SIZE at a time behind the same numbered pager the feed uses; the
// pager only appears once a bundle actually has more than one page.
//
// INVARIANT: the member list comes verbatim out of the decrypted,
// SIGNATURE-VERIFIED StreamType::Content of the signed BundleBody. Paging may
// only ever `slice()` that already-verified in-memory array — never sort it,
// never filter it, never re-order it. And `downloadAll` deliberately ignores the
// visible window: a button labelled "Download all" that silently skipped members
// off-page would be data loss.
const MEMBER_PAGE_SIZE = 60;

// STACKED LAZY MOUNT. A page of 60 fully-opening embedded viewers used to mount
// in ONE render, and every one of them calls open_content. On a 620-member bundle
// that burst drained the server's 30-challenges-per-60s budget in well under a
// second and painted a wall of "Could not open this item / Sign-in failed."
// Members are now mounted only as they scroll into view, so the number of opens
// in flight is bounded by what actually fits on screen (which also stops a slow
// network from queueing 60 opens behind one another).
//
// One viewport of pre-load either side keeps scrolling smooth without opening the
// whole page ahead of the user.
const STACK_PRELOAD_MARGIN = "400px 0px";
// Hosts WITHOUT IntersectionObserver: mount a small bounded prefix and leave the
// rest behind their own "Load item N" buttons. The shipped host (WebView2) always
// has IntersectionObserver, so this only guards an exotic one — but it must never
// degrade back to mounting the whole page, which is the bug above.
const STACK_FALLBACK_MOUNT = 4;

// DOWNLOAD-ALL RETRY. A throttled server answers `rate_limited` (HTTP 429), which
// is transient by definition — retrying it is the difference between "590 files
// silently missing" and "590 files saved a minute later". Bounded rounds with a
// growing backoff; the server's own Retry-After (UiError.retry_after_s) wins when
// it sends one.
const RATE_LIMIT_ROUNDS = 3;
const RATE_LIMIT_BACKOFF_MS = [3_000, 10_000, 30_000];
// Never sit on a wait longer than this, whatever the server asks for — the batch
// must stay interruptible and the UI must not look wedged.
const RATE_LIMIT_MAX_WAIT_MS = 120_000;

// --- Retained bundle state --------------------------------------------------
// Module-level, exactly like feed-screen.ts's `retained`, and for the same two
// reasons — plus a third that is specific to bundles:
//  1. Returning from a member must land on the page the member was ON, not page 1
//     (the screen used to hard-reset memberPage on every mount).
//  2. Re-entering the bundle must NOT re-run open_bundle. That call verifies and
//     decrypts the whole signed bundle over an authed channel: doing it again per
//     member viewed is a second login per item, which is exactly what pushed the
//     account into the server's challenge budget.
//  3. It is where the VIEWER gets its next/previous order from. That order MUST be
//     the SIGNED, authoritative member list out of the verified BundleBody
//     (commands/bundle.rs: "NEVER read members from a server-served listing"), so
//     the viewer reads THIS retained copy of what open_bundle returned and never
//     re-derives an order from a feed listing, the index, or the DOM.
//
// NOTE ON THE IMPORT CYCLE: media-viewer.ts imports the helpers below while this
// module imports media-viewer.ts for its element definition. That cycle is
// init-safe in both load orders because neither module touches the other's
// bindings at module-evaluation time — only inside methods, long after both
// bodies have run.
interface RetainedBundle {
  // The verified BundleView exactly as open_bundle returned it. Never mutated.
  view: BundleView;
  // 0-based member page the user was last on.
  page: number;
  scrollY: number;
  // file_id → content version LEARNED from a successful open this session. The
  // signed BundleBody carries no member versions, so this is how a re-open gets
  // to skip the network entirely (see `memberVersion`).
  versions: Map<string, number>;
}
// Bounded so a long session that browsed many bundles cannot grow without limit;
// Map iteration order is insertion order, so the oldest entry is the first key.
const RETAINED_MAX = 8;
const retained = new Map<string, RetainedBundle>();

function putRetained(bundleId: string, view: BundleView): RetainedBundle {
  const prior = retained.get(bundleId);
  const entry: RetainedBundle = {
    view,
    page: 0,
    scrollY: 0,
    // Keep versions learned earlier this session — they are keyed by file id and
    // a re-open of the same bundle does not invalidate them.
    versions: prior?.versions ?? new Map<string, number>(),
  };
  retained.delete(bundleId);
  retained.set(bundleId, entry);
  while (retained.size > RETAINED_MAX) {
    const oldest = retained.keys().next();
    if (oldest.done) break;
    retained.delete(oldest.value);
  }
  return entry;
}

/** One member's neighbours inside the SIGNED order of an already-opened bundle. */
export interface BundleNeighbours {
  /** 0-based position of the current member in the signed member list. */
  index: number;
  total: number;
  prev: BundleMemberView | null;
  next: BundleMemberView | null;
}

/**
 * The previous/next member around `fileId` in bundle `bundleId`, or null when
 * this session has not opened (and verified) that bundle — in which case there is
 * NO authoritative order available and the caller must offer no navigation rather
 * than invent one from a server-served listing.
 *
 * A bundle may legitimately list the same file twice; the first occurrence wins,
 * which keeps the walk deterministic.
 */
export function bundleNeighbours(bundleId: string, fileId: string): BundleNeighbours | null {
  const entry = retained.get(bundleId);
  if (!entry) return null;
  const members = entry.view.members;
  const index = members.findIndex((m) => m.file_id === fileId);
  if (index < 0) return null;
  return {
    index,
    total: members.length,
    prev: index > 0 ? members[index - 1] : null,
    next: index + 1 < members.length ? members[index + 1] : null,
  };
}

/**
 * Remember that the user is on `fileId`, so returning to the gallery lands on the
 * page CONTAINING it. Called by the viewer on every step of a next/previous walk —
 * a walk that crosses a page boundary must not drop the user back on page 1.
 */
export function rememberBundlePageFor(bundleId: string, fileId: string): void {
  const entry = retained.get(bundleId);
  if (!entry) return;
  const index = entry.view.members.findIndex((m) => m.file_id === fileId);
  if (index < 0) return;
  entry.page = Math.floor(index / MEMBER_PAGE_SIZE);
}

/**
 * Record a content version learned from a SUCCESSFUL open/decrypt of a member.
 * Versions below 1 are rejected: 0 is the "unknown" sentinel on the DTO and a
 * real version always starts at 1.
 */
export function rememberMemberVersion(bundleId: string, fileId: string, version: number): void {
  if (!Number.isInteger(version) || version <= 0) return;
  retained.get(bundleId)?.versions.set(fileId, version);
}

/**
 * The version to open `member` at, or undefined when it is not known.
 *
 * Passing a version lets open_content/decrypt_card short-circuit on the content
 * cache BEFORE any network or reauth. Passing a BOGUS one is worse than passing
 * none: `open_content_inner` gates its second (post-fetch) cache check on the
 * version being absent, so a 0 would lose both. Hence the strict `> 0` filter on
 * both the DTO field and the learned value.
 */
export function memberVersion(bundleId: string, member: BundleMemberView): number | undefined {
  const fromDto = member.version;
  if (typeof fromDto === "number" && Number.isInteger(fromDto) && fromDto > 0) return fromDto;
  const learned = retained.get(bundleId)?.versions.get(member.file_id);
  return typeof learned === "number" && learned > 0 ? learned : undefined;
}

// One member queued for (or retried by) Download all. `savePath` is allocated
// ONCE per batch so a retry writes to the same de-duplicated name instead of
// minting "member-3 (2).png" on every attempt.
interface DownloadTarget {
  /** 1-based position in the WHOLE member list (what the report shows the user). */
  position: number;
  fileId: string;
  name: string;
  savePath: string;
}

interface DownloadFailure {
  target: DownloadTarget;
  code: string;
  message: string;
  retryAfterS: number | null;
}

export class BundleScreen extends HTMLElement {
  private view: BundleView | null = null;
  private mode: BundleViewMode = readBundleViewMode();
  // 0-based page into `view.members` (presentation only — never mutates it).
  private memberPage = 0;
  private pagerFocus: PagerFocus | undefined;
  // Render-generation guard (Issue 1): a monotonically increasing token. A
  // debounced setMode schedules a re-render tagged with the current generation;
  // if a newer toggle bumps the generation first, the stale scheduled render is
  // dropped. This shrinks the window in which rapid toggles fan out overlapping
  // member loads that would contend the connect lock.
  private renderGen = 0;
  private modeTimer: ReturnType<typeof setTimeout> | null = null;
  // Stacked lazy mount: the observer plus the not-yet-mounted placeholders it
  // watches. Rebuilt on every render and torn down on disconnect.
  private observer: IntersectionObserver | null = null;
  private pending = new Map<Element, BundleMemberView>();
  // Download-all: the still-failed members of the last batch (what "Retry failed
  // downloads" re-runs) and a single-flight guard.
  private dlFailures: DownloadFailure[] = [];
  private dlRunning = false;

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
        <section id="bd-dl-report" class="bundle-dl-report" aria-labelledby="bd-dl-h" hidden>
          <h2 id="bd-dl-h">Download results</h2>
          <p id="bd-dl-progress" class="bundle-dl-progress"></p>
          <p id="bd-dl-summary" role="status" aria-live="polite"></p>
          <ul id="bd-dl-failures" class="bundle-dl-failures"></ul>
          <div class="bundle-dl-actions">
            <button id="bd-dl-retry" type="button" class="secondary" hidden>Retry failed downloads</button>
            <button id="bd-dl-dismiss" type="button" class="secondary">Dismiss</button>
          </div>
        </section>
        <div id="bd-members"></div>
        <nav id="bd-pager" class="pager" aria-label="Bundle member pages" hidden></nav>
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
    (this.querySelector("#bd-dl-retry") as HTMLButtonElement).addEventListener("click", () =>
      void this.retryFailedDownloads(),
    );
    (this.querySelector("#bd-dl-dismiss") as HTMLButtonElement).addEventListener("click", () =>
      this.hideDownloadReport(),
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

    // Already opened this session? Reuse the verified member list and the page the
    // user was on. This is what makes "back to the bundle" free: no second
    // open_bundle (a full verify + decrypt over an authed channel) per item viewed,
    // and no snap back to page 1.
    const prior = retained.get(id);
    if (prior) {
      this.view = prior.view;
      this.memberPage = prior.page;
      this.applyBundleChrome(prior.view);
      this.render();
      window.requestAnimationFrame(() => window.scrollTo(0, prior.scrollY));
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
      this.memberPage = 0;
      putRetained(id, view);
      this.applyBundleChrome(view);
      this.render();
    } catch (x) {
      this.fail(bundleErr(x));
    }
  }

  // The status line + the toolbar affordances that follow from a loaded bundle.
  // Shared by the fresh-open path and the retained (returning-from-a-member) path
  // so the two can never drift.
  private applyBundleChrome(view: BundleView) {
    const n = view.members.length;
    // One page ⇒ today's exact line; more ⇒ the honest windowed line, so the
    // status never claims to be showing members that are on another page.
    (this.querySelector("#bd-status") as HTMLElement).textContent =
      n === 0
        ? "This bundle is empty."
        : n <= MEMBER_PAGE_SIZE
        ? `${n} item${n === 1 ? "" : "s"}.`
        : showingLabel(this.memberPage, MEMBER_PAGE_SIZE, n);
    // Download-all only makes sense once there is at least one member.
    (this.querySelector("#bd-download-all") as HTMLButtonElement).disabled = n === 0;
    // Owner-only "Delete bundle" (bundles Task 6.2): shown only to the author.
    (this.querySelector("#bd-delete") as HTMLButtonElement).hidden = !view.mine;
    // Share… is available to ANY wrap-holder who could open the bundle (not
    // ownership-gated) — mirrors the viewer's can_share affordance. Except a
    // RECOVERY principal, whose reshare is refused in Rust
    // (`recovery_share_unsupported`) — hidden rather than left as a dead end.
    (this.querySelector("#bd-share") as HTMLButtonElement).hidden =
      getPrincipalKind() === "recovery";
  }

  private fail(msg: string) {
    this.view = null;
    (this.querySelector("#bd-status") as HTMLElement).textContent = msg;
    (this.querySelector("#bd-members") as HTMLElement).replaceChildren();
    const nav = this.querySelector("#bd-pager") as HTMLElement | null;
    if (nav) {
      nav.hidden = true;
      nav.replaceChildren();
    }
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
    // Stop watching placeholders that are about to be detached.
    this.observer?.disconnect();
    this.observer = null;
    this.pending.clear();
    // Remember where the user was, so returning restores the scroll position too.
    const entry = this.view ? retained.get(this.view.file_id) : undefined;
    if (entry) entry.scrollY = window.scrollY;
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
  // de-duped so two same-kind members never collide.
  //
  // FAILURES ARE NOT SWALLOWED. This used to catch-and-ignore every member error and
  // then toast a bare "Downloaded N of M" — so a throttled run on a large bundle
  // reported *success* while hundreds of files were silently missing, with no way to
  // tell which ones or why. Now each failure is captured with its sanitized code and
  // message, rate-limited ones are retried with a backoff, and whatever is still
  // missing is listed per-member in a report panel with a Retry button.
  private async downloadAll() {
    if (!this.view || this.view.members.length === 0) return;
    if (this.dlRunning) return;
    // EVERY member, not the visible page. The button says "all"; silently
    // dropping the members that happen to be off-page would be data loss for the
    // user. Member paging is a rendering concern ONLY — this list is deliberately
    // un-sliced, and the per-member `member-<n>` names stay indexed against the
    // whole list so they don't shift with the current page.
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
      const targets: DownloadTarget[] = [];
      for (let i = 0; i < total; i++) {
        const m = members[i];
        const name = dedupeName(downloadName(m.file_type, `member-${i + 1}`), used);
        targets.push({
          position: i + 1,
          fileId: m.file_id,
          name,
          savePath: `${folder}${sep}${name}`,
        });
      }
      await this.runDownloads(targets, false);
    } finally {
      btn.disabled = false;
    }
  }

  // Re-run just the members that are still missing, into the SAME folder and under
  // the SAME already-de-duplicated names, so a retry overwrites its own failed
  // attempt instead of accumulating "member-3 (2).png".
  private async retryFailedDownloads() {
    if (this.dlRunning || this.dlFailures.length === 0) return;
    const targets = this.dlFailures.map((f) => f.target);
    const dl = this.querySelector("#bd-download-all") as HTMLButtonElement;
    dl.disabled = true;
    try {
      await this.runDownloads(targets, true);
    } finally {
      dl.disabled = this.view === null || this.view.members.length === 0;
    }
  }

  // Run one batch of downloads to completion, retrying `rate_limited` members with
  // a growing backoff, then report honestly. Returns nothing; everything the user
  // needs is in the report panel (and one toast whose severity matches the truth).
  private async runDownloads(targets: DownloadTarget[], isRetryPass: boolean) {
    // Per-item progress goes to a PLAIN paragraph, never the live region: a
    // 620-member batch would otherwise queue 620 screen-reader announcements. The
    // live `#bd-dl-summary` carries the one thing worth announcing — the outcome.
    const progress = this.querySelector("#bd-dl-progress") as HTMLElement;
    const retryBtn = this.querySelector("#bd-dl-retry") as HTMLButtonElement;
    (this.querySelector("#bd-dl-report") as HTMLElement).hidden = false;
    (this.querySelector("#bd-dl-summary") as HTMLElement).textContent = "";
    (this.querySelector("#bd-dl-failures") as HTMLElement).replaceChildren();
    retryBtn.hidden = true;
    this.dlRunning = true;
    const batchTotal = targets.length;
    let ok = 0;
    let done = 0;
    let queue = targets;
    // The throttled failures of the PREVIOUS round — they are what carry the
    // server's Retry-After, so they are what sizes the next wait.
    let throttledPrev: DownloadFailure[] = [];
    const permanent: DownloadFailure[] = [];
    try {
      for (let round = 0; round <= RATE_LIMIT_ROUNDS; round++) {
        if (round > 0) {
          const waitMs = rateLimitWaitMs(round, throttledPrev);
          progress.textContent =
            `Server is rate limiting — waiting ${Math.round(waitMs / 1000)}s, then retrying ` +
            `${queue.length} item(s) (attempt ${round + 1} of ${RATE_LIMIT_ROUNDS + 1})…`;
          await sleep(waitMs);
          if (!this.isConnected) return;
        }
        const throttled: DownloadFailure[] = [];
        for (const t of queue) {
          // The user navigated away mid-batch: stop rather than keep an invisible
          // screen writing files and reporting into detached nodes.
          if (!this.isConnected) return;
          done++;
          progress.textContent =
            round === 0
              ? `Downloading ${done} of ${batchTotal}…`
              : `Retrying item ${t.position} (${queue.length} left)…`;
          try {
            await serial(() =>
              call<string>("download_content", {
                req: { file_id: t.fileId, save_path: t.savePath },
              }),
            );
            ok++;
          } catch (x) {
            const failure: DownloadFailure = { target: t, ...describeFailure(x) };
            if (round < RATE_LIMIT_ROUNDS && isRateLimited(failure)) throttled.push(failure);
            else permanent.push(failure);
          }
        }
        if (throttled.length === 0) break;
        queue = throttled.map((f) => f.target);
        throttledPrev = throttled;
      }
      this.dlFailures = permanent;
      this.renderDownloadReport(ok, batchTotal, permanent, isRetryPass);
    } finally {
      this.dlRunning = false;
    }
  }

  // The honest outcome. A partial batch is NEVER reported as success: the toast is
  // an error, the summary names how many are missing, and every missing member is
  // listed with its position, filename and sanitized reason so the user knows
  // exactly what to re-fetch.
  private renderDownloadReport(
    ok: number,
    total: number,
    failures: DownloadFailure[],
    isRetryPass: boolean,
  ) {
    const summary = this.querySelector("#bd-dl-summary") as HTMLElement;
    const list = this.querySelector("#bd-dl-failures") as HTMLElement;
    const retryBtn = this.querySelector("#bd-dl-retry") as HTMLButtonElement;
    // The ticker has served its purpose; the outcome below replaces it.
    (this.querySelector("#bd-dl-progress") as HTMLElement).textContent = "";
    list.replaceChildren();
    if (failures.length === 0) {
      const msg = isRetryPass
        ? `Retried ${total} item(s) — all saved.`
        : `Downloaded all ${total} item(s).`;
      summary.textContent = msg;
      retryBtn.hidden = true;
      toast("success", msg);
      return;
    }
    const msg = isRetryPass
      ? `Retried ${total} item(s): ${ok} saved, ${failures.length} still missing.`
      : `Downloaded ${ok} of ${total}. ${failures.length} item(s) were NOT saved.`;
    summary.textContent = msg;
    for (const f of failures) {
      const li = document.createElement("li");
      const who = document.createElement("strong");
      who.textContent = `Item ${f.target.position} — ${f.target.name}`;
      const why = document.createElement("span");
      // Sanitized backend message + its machine code, so a support conversation
      // has something precise to go on.
      why.textContent = ` — ${f.message} (${f.code})`;
      li.append(who, why);
      list.appendChild(li);
    }
    retryBtn.hidden = false;
    toast("error", `${msg} See "Download results" for which ones and why.`);
  }

  private hideDownloadReport() {
    const report = this.querySelector("#bd-dl-report") as HTMLElement;
    report.hidden = true;
    (this.querySelector("#bd-dl-failures") as HTMLElement).replaceChildren();
    (this.querySelector("#bd-dl-progress") as HTMLElement).textContent = "";
    (this.querySelector("#bd-dl-summary") as HTMLElement).textContent = "";
    (this.querySelector("#bd-dl-retry") as HTMLButtonElement).hidden = true;
    this.dlFailures = [];
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
      // The bundle is gone: drop the retained copy so nothing (including the
      // viewer's next/previous walk) keeps navigating a deleted member list.
      retained.delete(bundleId);
      this.view = null;
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
    // A re-render detaches every placeholder the observer was watching.
    this.observer?.disconnect();
    this.observer = null;
    this.pending.clear();
    const container = this.querySelector("#bd-members") as HTMLElement;
    container.replaceChildren();
    if (!this.view) return;
    const view = this.view;
    container.className = this.mode === "gallery" ? "bundle-gallery" : "bundle-stack";
    container.setAttribute("role", "list");

    // Window the SIGNED member list by slicing only — no sort, no filter, no
    // re-order. `slice` on an out-of-range page yields [], which the clamp below
    // makes unreachable.
    const all = view.members;
    const count = pageCount(all.length, MEMBER_PAGE_SIZE);
    this.memberPage = clampPage(this.memberPage, count);
    const start = this.memberPage * MEMBER_PAGE_SIZE;
    const visible = all.slice(start, start + MEMBER_PAGE_SIZE);
    this.renderMemberPager(count);

    if (this.mode === "stacked") this.observer = this.makeStackObserver();

    for (let i = 0; i < visible.length; i++) {
      const m = visible[i];
      // 1-based position in the WHOLE bundle, so a label never renumbers per page.
      const position = start + i + 1;
      const version = memberVersion(view.file_id, m);
      if (this.mode === "gallery") {
        // Gallery: a decrypt-on-tap <media-card> grid cell per member.
        const card = document.createElement("media-card");
        card.setAttribute("file-id", m.file_id);
        card.setAttribute("file-type", m.file_type);
        card.setAttribute("role", "listitem");
        // Only when actually known: <media-card> forwards this straight into
        // decrypt_card and into the viewer link, where an unknown/0 version would
        // defeat both content-cache checks instead of enabling one.
        if (version !== undefined) card.setAttribute("version", String(version));
        card.setAttribute("return-bundle-id", view.file_id);
        container.appendChild(card);
      } else {
        // Stacked: each member is fully opened inline via an embedded
        // <media-viewer> (no landmark/focus chrome), in bundle order — but only
        // once it is actually on screen. Until then it is a placeholder carrying a
        // real "Load item N" button, which is also what keeps the list operable
        // for a keyboard user (a placeholder with nothing focusable in it could
        // never be reached, and so could never be opened).
        const item = document.createElement("section");
        item.className = "bundle-stack-item";
        item.setAttribute("role", "listitem");
        this.renderPlaceholder(item, m, position);
        container.appendChild(item);
        if (this.observer) {
          this.pending.set(item, m);
          this.observer.observe(item);
        } else if (i < STACK_FALLBACK_MOUNT) {
          // No IntersectionObserver on this host: open a bounded prefix and leave
          // the rest to their buttons.
          this.mountMember(item, m);
        }
      }
    }
  }

  // Watches Stacked placeholders and mounts each one as it comes into view (plus
  // one screen of pre-load). Returns null on a host without IntersectionObserver.
  private makeStackObserver(): IntersectionObserver | null {
    if (typeof IntersectionObserver === "undefined") return null;
    return new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (!e.isIntersecting) continue;
          const item = e.target as HTMLElement;
          const m = this.pending.get(item);
          if (m) this.mountMember(item, m);
        }
      },
      { rootMargin: STACK_PRELOAD_MARGIN },
    );
  }

  // The not-yet-opened stand-in for a Stacked member: a shimmer placeholder (which
  // also gives the row real height, so 60 zero-height rows can't all intersect at
  // once and defeat the laziness) plus an explicit load control.
  private renderPlaceholder(item: HTMLElement, m: BundleMemberView, position: number) {
    const pending = document.createElement("div");
    pending.className = "bundle-stack-pending";
    // Load-bearing, not cosmetic: a ZERO-height placeholder would put all 60 rows
    // inside the viewport at once and every one of them would intersect on the
    // first frame — i.e. exactly the fan-out this lazy mount exists to prevent.
    // <skeleton-card> already carries min-height: 15.5rem in all three skins; this
    // is the floor that survives a skin that ever drops it.
    pending.style.minHeight = "12rem";
    pending.appendChild(document.createElement("skeleton-card"));
    const load = document.createElement("button");
    load.type = "button";
    load.className = "secondary";
    load.textContent = `Load item ${position}`;
    load.setAttribute("aria-label", `Load item ${position} of this bundle`);
    load.addEventListener("click", () => this.mountMember(item, m));
    pending.appendChild(load);
    item.replaceChildren(pending);
  }

  // Replace a placeholder with the real embedded viewer. Idempotent: the observer
  // and the Load button can both fire for the same row.
  private mountMember(item: HTMLElement, m: BundleMemberView) {
    if (item.dataset.mounted === "1") return;
    item.dataset.mounted = "1";
    this.pending.delete(item);
    this.observer?.unobserve(item);
    const viewer = document.createElement("media-viewer");
    viewer.setAttribute("file-id", m.file_id);
    viewer.setAttribute("embedded", "");
    if (this.view) {
      // Tells the embedded viewer which bundle it is a member of, so the version
      // it verifies is remembered for later opens of the same member. It does NOT
      // give an embedded viewer next/previous chrome — that is routed-only.
      viewer.setAttribute("bundle-id", this.view.file_id);
      const version = memberVersion(this.view.file_id, m);
      if (version !== undefined) viewer.setAttribute("version", String(version));
    }
    item.replaceChildren(viewer);
  }

  // The numbered member pager. Shown ONLY when the bundle has more than one
  // page (> MEMBER_PAGE_SIZE members), so every bundle that renders today keeps
  // rendering byte-identically.
  private renderMemberPager(count: number) {
    const nav = this.querySelector("#bd-pager") as HTMLElement;
    if (count <= 1) {
      nav.hidden = true;
      nav.replaceChildren();
      return;
    }
    const total = this.view?.members.length ?? 0;
    (this.querySelector("#bd-status") as HTMLElement).textContent = showingLabel(
      this.memberPage,
      MEMBER_PAGE_SIZE,
      total,
    );
    const focus = this.pagerFocus;
    this.pagerFocus = undefined;
    renderPager(nav, {
      page: this.memberPage,
      count,
      label: "Bundle member pages",
      focus,
      onGo: (p, from) => {
        const next = clampPage(p, count);
        if (next === this.memberPage) return;
        this.memberPage = next;
        // Retain it, so opening a member from this page and coming back lands
        // here rather than on page 1.
        const entry = this.view ? retained.get(this.view.file_id) : undefined;
        if (entry) entry.page = next;
        this.pagerFocus = from;
        this.render();
      },
    });
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

// Pull the sanitized `{ code, message, retry_after_s }` out of a rejected command.
// Defensive on every field: an older backend sends no `retry_after_s` at all, and
// a non-UiError rejection (a thrown string, a DOM exception) must still produce a
// row the user can read rather than "[object Object]".
function describeFailure(x: unknown): { code: string; message: string; retryAfterS: number | null } {
  const e = (x && typeof x === "object" ? x : {}) as {
    code?: unknown;
    message?: unknown;
    retry_after_s?: unknown;
  };
  const code = typeof e.code === "string" && e.code !== "" ? e.code : "unknown";
  const message =
    typeof e.message === "string" && e.message !== ""
      ? e.message
      : "This item could not be downloaded.";
  const retryAfterS =
    typeof e.retry_after_s === "number" && Number.isFinite(e.retry_after_s) && e.retry_after_s > 0
      ? e.retry_after_s
      : null;
  return { code, message, retryAfterS };
}

// Is this failure the server throttling us (and therefore worth retrying)?
//
// The authoritative signal is the `rate_limited` code. It is matched DEFENSIVELY —
// by code first, then by shape, then by the human message — because the Rust side
// is only now growing that code and an exe paired with a newer ui/dist must not
// silently downgrade a throttled batch into "590 permanent failures". Over-matching
// is cheap here: retries are bounded, so the worst case is a couple of extra
// attempts on something that was never going to succeed.
function isRateLimited(f: { code: string; message: string }): boolean {
  const code = f.code.toLowerCase();
  if (code === "rate_limited" || code === "rate-limited" || code === "ratelimited") return true;
  if (/rate[_\- ]?limit|too[_\- ]?many[_\- ]?requests|throttl/.test(code)) return true;
  return /rate limit|too many requests|try again (shortly|later|in )/i.test(f.message);
}

// How long to wait before retry round `round` (1-based). The server's own
// Retry-After wins when it sent one (that is the real reset interval, not a
// guess); otherwise a fixed growing backoff. Always clamped so the batch stays
// responsive and the panel never looks wedged.
//
// Deliberately NOT proportional to the backlog: scaling the wait by 600 queued
// members would turn a retry into an hours-long sleep. Bounded rounds plus the
// explicit "Retry failed downloads" button are the escape hatch instead.
function rateLimitWaitMs(round: number, throttled: DownloadFailure[]): number {
  const fallback = RATE_LIMIT_BACKOFF_MS[Math.min(round, RATE_LIMIT_BACKOFF_MS.length) - 1];
  let serverAsk = 0;
  for (const f of throttled) {
    if (f.retryAfterS !== null && f.retryAfterS * 1000 > serverAsk) serverAsk = f.retryAfterS * 1000;
  }
  return Math.min(Math.max(fallback, serverAsk), RATE_LIMIT_MAX_WAIT_MS);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

customElements.define("bundle-screen", BundleScreen);
