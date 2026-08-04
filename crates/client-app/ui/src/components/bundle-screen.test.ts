import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  normalizeBundleViewMode,
  readBundleViewMode,
  writeBundleViewMode,
} from "../core/bundle-view.ts";
import { settingsStore } from "../core/settings-store-instance.ts";

// --- Store-backed view-mode persistence (DOM-free) -------------------------
// The chosen view mode ("gallery" | "stacked") is a non-secret UI preference now
// persisted in the backend settings.json (settings.ui.bundle_view) via the shared
// settings store — no browser localStorage. The helpers are pure/guardable so they
// unit-test without a DOM (the node harness has no Tauri host).

test("normalizeBundleViewMode coerces to a valid mode (default gallery)", () => {
  assert.equal(normalizeBundleViewMode("stacked"), "stacked");
  assert.equal(normalizeBundleViewMode("gallery"), "gallery");
  assert.equal(normalizeBundleViewMode("nope"), "gallery");
  assert.equal(normalizeBundleViewMode(null), "gallery");
  assert.equal(normalizeBundleViewMode(undefined), "gallery");
});

test("read reflects the settings store; write patches it locally", () => {
  settingsStore.patchLocal({ ui: { bundle_view: "stacked" } });
  assert.equal(readBundleViewMode(), "stacked");
  writeBundleViewMode("gallery");
  assert.equal(settingsStore.get().ui.bundle_view, "gallery");
  assert.equal(readBundleViewMode(), "gallery");
});

// --- Source-structural assertions on the routed screen ----------------------
// The screen imports the Tauri API (via core/rpc.ts) so it cannot be mounted in
// plain Node; the a11y source lint (a11y.test.ts) covers landmark/focus/live/XSS.
// Here we assert the load-bearing wiring: it reads the id from the hash, drives
// open_bundle, reuses <media-card> per member for Gallery, and renders distinct
// per-member blocks for Stacked, using the persistence helper.
const src = readFileSync("src/components/bundle-screen.ts", "utf8");

test("bundle-screen reads the id from the #/bundle?id= hash query", () => {
  assert.match(src, /URLSearchParams\(location\.hash\.split\("\?"\)\[1\]/);
  assert.match(src, /\.get\("id"\)/);
});

test("bundle-screen drives the open_bundle command with the file_id", () => {
  assert.match(src, /"open_bundle"/);
  assert.match(src, /file_id/);
});

test("Gallery mode renders a decrypt-on-tap <media-card> per member", () => {
  assert.match(src, /createElement\("media-card"\)/);
  assert.match(src, /setAttribute\("file-type"/);
});

test("Stacked mode renders a fully-opened embedded <media-viewer> per member", () => {
  assert.match(src, /createElement\("media-viewer"\)/);
  assert.match(src, /setAttribute\("file-id"/);
  assert.match(src, /setAttribute\("embedded"/);
  assert.match(src, /bundle-stack-item/);
});

test("Gallery and Stacked render provably distinct element types", () => {
  // The whole point of the two modes: cards vs inline-opened viewers.
  assert.match(src, /createElement\("media-card"\)/);
  assert.match(src, /createElement\("media-viewer"\)/);
});

test("bundle-screen has a two-button Gallery/Stacked toggle with aria state", () => {
  assert.match(src, /Gallery/);
  assert.match(src, /Stacked/);
  assert.match(src, /aria-pressed/);
});

test("bundle-screen persists the mode via the bundle-view helper", () => {
  assert.match(src, /readBundleViewMode/);
  assert.match(src, /writeBundleViewMode/);
});

// --- Issue 1 (frontend): render-generation guard + debounced view switch -----
// Rapid Gallery⇄Stacked toggling must not fan out overlapping member loads that
// race the connect lock. setMode debounces the expensive re-render and tags each
// scheduled render with a generation token so a superseded one is dropped;
// re-render tears down prior children (replaceChildren) so their in-flight loads
// are abandoned. disconnect clears any pending timer.

test("bundle-screen carries a render-generation token", () => {
  assert.match(src, /renderGen/, "must track a render generation");
});

test("setMode debounces the re-render with a timer", () => {
  assert.match(src, /setTimeout\(/, "setMode must schedule the re-render on a timer");
  assert.match(src, /clearTimeout\(/, "a pending re-render timer must be cancellable");
});

test("a superseded scheduled render is dropped via the generation guard", () => {
  // The scheduled callback bails when its captured generation is stale.
  assert.match(src, /!==\s*this\.renderGen/, "scheduled render must guard on a stale generation");
});

test("disconnect clears the pending re-render timer", () => {
  assert.match(src, /disconnectedCallback\(\)\s*\{[\s\S]*clearTimeout/, "must clear the timer on disconnect");
});

// --- F3: numbered member paging (windowing the SIGNED member list) -----------
// The wire format allows 65535 members and there is no cap, so a large bundle
// would otherwise mount thousands of self-decrypting cards (or, in Stacked mode,
// thousands of fully-opened viewers) at once. Members are now shown 60 at a time
// behind the same numbered pager the feed uses.

test("member paging windows at 60 and only ever slices", () => {
  assert.match(src, /MEMBER_PAGE_SIZE\s*=\s*60/, "the member page size must be 60");
  assert.match(
    src,
    /all\.slice\(start, start \+ MEMBER_PAGE_SIZE\)/,
    "the visible window must be a plain slice of the verified member array",
  );
});

test("the signed member list is never re-ordered or filtered", () => {
  // The members come verbatim out of the decrypted, SIGNATURE-VERIFIED
  // StreamType::Content of the signed BundleBody. Paging is presentation only:
  // a sort or a filter here would silently diverge from what was signed.
  assert.doesNotMatch(src, /members\.sort\(/, "the signed member order must not be sorted");
  assert.doesNotMatch(src, /members\.filter\(/, "the signed member list must not be filtered");
  assert.doesNotMatch(src, /members\.reverse\(/, "the signed member order must not be reversed");
});

test("the member pager appears ONLY when a bundle exceeds one page", () => {
  assert.match(
    src,
    /private renderMemberPager\(count: number\)\s*\{\s*[\s\S]{0,200}?if \(count <= 1\)\s*\{[\s\S]{0,120}?nav\.hidden = true/,
    "a single-page bundle must render no pager at all",
  );
  assert.match(
    src,
    /<nav id="bd-pager"[^>]*aria-label="Bundle member pages"[^>]*hidden><\/nav>/,
    "the pager host must be a static, labelled, initially-hidden <nav>",
  );
  assert.match(src, /renderPager\(/, "the pager must reuse the shared core/pager.ts control");
});

test("downloadAll still covers EVERY member, not the visible page", () => {
  // A button labelled "Download all" that silently skipped off-page members
  // would be data loss. Pin that downloadAll takes the WHOLE array and loops it.
  const block = src.match(/private async downloadAll\(\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(block, "downloadAll must exist");
  // Assert on CODE, not prose: the body documents the invariant in a comment that
  // necessarily names the page size, so strip line comments first.
  const dl = block.replace(/^\s*\/\/.*$/gm, "");
  assert.match(dl, /const members = this\.view\.members;/, "downloadAll must take every member");
  assert.doesNotMatch(dl, /\.slice\(/, "downloadAll must NOT window the member list");
  assert.doesNotMatch(dl, /MEMBER_PAGE_SIZE/, "downloadAll must not know about paging at all");
  assert.doesNotMatch(dl, /memberPage/, "downloadAll must not depend on the current page");
  // …and it loops over the full length, naming members by their index in the
  // whole list (so names don't shift with the visible page).
  assert.match(dl, /const total = members\.length;/, "the batch total is the full member count");
  assert.match(dl, /for \(let i = 0; i < total; i\+\+\)/, "the loop must cover the full list");
  assert.match(dl, /`member-\$\{i \+ 1\}`/, "member names stay indexed against the whole list");
});

test("opening a bundle starts on page 1", () => {
  const load = src.match(/private async load\(id: string\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(load, "load must exist");
  assert.match(load, /this\.memberPage = 0;/, "a freshly opened bundle must start at page 1");
});

// --- Stacked fan-out must be BOUNDED by what is on screen --------------------
// A page of MEMBER_PAGE_SIZE (60) fully-opening embedded viewers used to mount in
// ONE render, and every one of them calls open_content. On a 620-member bundle
// that burst drained the server's 30-challenges-per-60s budget in under a second
// and painted a wall of "Could not open this item / Sign-in failed." Members must
// therefore mount lazily, as they scroll into view.

test("Stacked members mount lazily, never all at once", () => {
  assert.match(src, /new IntersectionObserver\(/, "lazy mount must use an IntersectionObserver");
  assert.match(src, /rootMargin: STACK_PRELOAD_MARGIN/, "the observer must pre-load by a margin");
  const render = src.match(/private render\(\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(render, "render must exist");
  // The render loop may only lay down placeholders — the viewer itself is created
  // in the mount step, which is what the observer (or the Load button) drives.
  assert.doesNotMatch(
    render,
    /createElement\("media-viewer"\)/,
    "render must not mount an embedded viewer per member",
  );
  assert.match(render, /this\.observer\.observe\(item\)/, "each placeholder must be observed");
});

test("a host without IntersectionObserver still bounds the fan-out", () => {
  // The shipped host (WebView2) always has it; the fallback must NOT degrade back
  // to mounting the whole page, only a small bounded prefix.
  assert.match(src, /typeof IntersectionObserver === "undefined"/, "the fallback must be guarded");
  assert.match(src, /STACK_FALLBACK_MOUNT\s*=\s*\d+/, "the fallback must mount a bounded prefix");
  assert.match(src, /i < STACK_FALLBACK_MOUNT/, "the fallback prefix must be applied by index");
});

test("an unmounted Stacked member is keyboard-reachable and has real height", () => {
  // A placeholder with nothing focusable in it can never be reached by Tab, so it
  // could never be opened without a mouse; and a zero-height placeholder would put
  // all 60 rows on screen at once, defeating the laziness entirely.
  assert.match(src, /load\.type = "button";/, "the load control must be a real <button>");
  assert.match(src, /"aria-label", `Load item \$\{position\} of this bundle`/, "…and be labelled");
  assert.match(src, /pending\.style\.minHeight/, "the placeholder must have a height floor");
});

test("mounting a Stacked member is idempotent and stops observing it", () => {
  const mount = src.match(/private mountMember\([\s\S]*?\n  \}/)?.[0];
  assert.ok(mount, "mountMember must exist");
  // The observer and the Load button can both fire for the same row.
  assert.match(mount, /item\.dataset\.mounted === "1"/, "a second mount must be a no-op");
  assert.match(mount, /this\.observer\?\.unobserve\(item\)/, "a mounted row must stop being watched");
});

test("the observer is torn down on re-render and on disconnect", () => {
  const render = src.match(/private render\(\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(render, "render must exist");
  assert.match(render, /this\.observer\?\.disconnect\(\)/, "a re-render must drop the old observer");
  const dis = src.match(/disconnectedCallback\(\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(dis, "disconnectedCallback must exist");
  assert.match(dis, /this\.observer\?\.disconnect\(\)/, "teardown must drop the observer");
});

// --- Download all: partial success is a FAILURE, and it is retryable ---------
// The old loop swallowed every member error in a bare `catch {}` and then toasted
// "Downloaded N of M" as a success tally — so a throttled run reported success
// while hundreds of files were silently missing, with no per-item detail, no
// reason and no retry.

test("a failed member is never swallowed", () => {
  const dl = src.match(/private async downloadAll\(\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(dl, "downloadAll must exist");
  assert.doesNotMatch(dl, /catch \{/, "a member failure must never be caught and ignored");
  const run = src.match(/private async runDownloads\([\s\S]*?\n  \}/)?.[0];
  assert.ok(run, "runDownloads must exist");
  assert.match(run, /describeFailure\(x\)/, "every failure must be captured with its code");
});

test("a partial batch is reported as an error, never as success", () => {
  const report = src.match(/private renderDownloadReport\([\s\S]*?\n  \}/)?.[0];
  assert.ok(report, "renderDownloadReport must exist");
  // The ONLY success toast is inside the zero-failure branch, which returns.
  assert.match(
    report,
    /if \(failures\.length === 0\)\s*\{[\s\S]*?toast\("success",[\s\S]*?return;\s*\}/,
    "success may only be toasted when nothing failed",
  );
  assert.equal(
    (report.match(/toast\("success"/g) ?? []).length,
    1,
    "there must be exactly one success toast, in the zero-failure branch",
  );
  assert.match(report, /toast\("error",/, "a partial batch must toast an error");
});

test("the report says WHICH members failed and WHY", () => {
  const report = src.match(/private renderDownloadReport\([\s\S]*?\n  \}/)?.[0];
  assert.ok(report, "renderDownloadReport must exist");
  assert.match(report, /f\.target\.position/, "each row must name the member position");
  assert.match(report, /f\.target\.name/, "…and the file it would have been saved as");
  assert.match(report, /f\.message/, "…and the sanitized reason");
  assert.match(report, /f\.code/, "…and its machine code");
  // Built via createElement/textContent — never interpolated into innerHTML.
  assert.match(report, /document\.createElement\("li"\)/);
  assert.match(report, /textContent/);
});

test("rate-limited members are retried, matched defensively on the code", () => {
  assert.match(src, /function isRateLimited/, "there must be a rate-limit predicate");
  assert.match(src, /code === "rate_limited"/, "the authoritative code must be matched by name");
  // The Rust code is only now growing `rate_limited`, so the predicate must also
  // recognise the failure by shape/message rather than dropping the whole batch.
  assert.match(src, /f\.message/, "the predicate must fall back to the message");
  const run = src.match(/private async runDownloads\([\s\S]*?\n  \}/)?.[0];
  assert.ok(run, "runDownloads must exist");
  assert.match(run, /isRateLimited\(failure\)/, "a throttled member must be re-queued");
  assert.match(run, /round < RATE_LIMIT_ROUNDS/, "retries must be bounded");
  assert.match(run, /await sleep\(waitMs\)/, "retries must back off");
  // The server's own Retry-After wins over the guess when it sent one.
  assert.match(src, /f\.retryAfterS !== null/, "Retry-After must be honoured");
});

test("a retry re-uses the SAME allocated filename", () => {
  // Otherwise every attempt mints "member-3 (2).png", "member-3 (3).png", …
  const retry = src.match(/private async retryFailedDownloads\(\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(retry, "retryFailedDownloads must exist");
  assert.match(retry, /this\.dlFailures\.map\(\(f\) => f\.target\)/, "it must re-run the SAME targets");
  assert.match(
    src,
    /<button id="bd-dl-retry" type="button"[^>]*>Retry failed downloads<\/button>/,
    "the retry control must be a real, labelled <button type=\"button\">",
  );
});

// --- Retained bundle state: the page, and the viewer's next/previous order ----

test("returning to an already-opened bundle restores its page without re-opening it", () => {
  const cc = src.match(/connectedCallback\(\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(cc, "connectedCallback must exist");
  assert.match(cc, /retained\.get\(id\)/, "the retained bundle must be consulted on mount");
  assert.match(cc, /this\.memberPage = prior\.page;/, "the retained page must be restored");
  // open_bundle verifies + decrypts the whole bundle over an authed channel:
  // re-running it per member viewed is a second login per item. Assert on CODE,
  // not prose — the body documents that invariant in a comment that names the
  // command — so strip line comments first.
  assert.doesNotMatch(
    cc.replace(/^\s*\/\/.*$/gm, ""),
    /open_bundle/,
    "a retained bundle must NOT re-run open_bundle",
  );
});

test("a fresh open retains the verified bundle", () => {
  const load = src.match(/private async load\(id: string\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(load, "load must exist");
  assert.match(load, /putRetained\(id, view\)/, "load must retain what open_bundle returned");
});

test("changing member page updates the retained page", () => {
  const pager = src.match(/private renderMemberPager\(count: number\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(pager, "renderMemberPager must exist");
  assert.match(pager, /entry\.page = next;/, "paging must be remembered for the return trip");
});

test("deleting a bundle drops its retained member list", () => {
  const del = src.match(/private async onDelete\(\)[\s\S]*?\n  \}/)?.[0];
  assert.ok(del, "onDelete must exist");
  assert.match(del, /retained\.delete\(bundleId\)/, "a deleted bundle must not stay navigable");
});

test("the retained store is bounded", () => {
  assert.match(src, /RETAINED_MAX\s*=\s*\d+/, "the retained map must have a cap");
  assert.match(src, /retained\.size > RETAINED_MAX/, "…and must evict past it");
});

test("neighbours come from the SIGNED member list only", () => {
  const fn = src.match(/export function bundleNeighbours[\s\S]*?\n\}/)?.[0];
  assert.ok(fn, "bundleNeighbours must be exported for the viewer");
  assert.match(fn, /entry\.view\.members/, "the order must be the verified BundleView's");
  // No verified order for this bundle ⇒ offer nothing, rather than guess one.
  assert.match(fn, /if \(!entry\) return null;/, "an un-opened bundle must yield no order");
});

test("a member version is only used when it is a REAL version", () => {
  // 0 is the DTO's "unknown" sentinel. Passing it would MISS the pre-network cache
  // AND make open_content skip its second (post-fetch) cache check, which is
  // strictly worse than passing nothing at all.
  const fn = src.match(/export function memberVersion[\s\S]*?\n\}/)?.[0];
  assert.ok(fn, "memberVersion must be exported");
  assert.match(fn, /Number\.isInteger\(fromDto\) && fromDto > 0/, "the DTO value must be > 0");
  assert.match(fn, /learned > 0 \? learned : undefined/, "a learned value must be > 0");
  assert.match(
    src,
    /if \(version !== undefined\) card\.setAttribute\("version", String\(version\)\)/,
    "the card attribute must be set only when a version is known",
  );
});

// --- The viewer's Next / Previous walk --------------------------------------
const viewer = readFileSync("src/components/media-viewer.ts", "utf8");

test("the viewer offers real, labelled Next/Previous controls", () => {
  assert.match(
    viewer,
    /<button id="vw-prev" type="button"[^>]*aria-label="Previous item"[^>]*>/,
    'Previous must be a real <button type="button"> with an explicit aria-label',
  );
  assert.match(
    viewer,
    /<button id="vw-next" type="button"[^>]*aria-label="Next item"[^>]*>/,
    'Next must be a real <button type="button"> with an explicit aria-label',
  );
  assert.match(
    viewer,
    /<nav id="vw-bundle-nav"[^>]*aria-label="Bundle navigation"[^>]*hidden>/,
    "the walk controls must ship hidden inside a labelled <nav>",
  );
  assert.match(viewer, /addEventListener\("click", \(\) => this\.goToMember/, "wired via addEventListener");
});

test("Next/Previous are disabled at the ends, not silent no-ops", () => {
  assert.match(viewer, /prev\.disabled = around\.prev === null;/);
  assert.match(viewer, /next\.disabled = around\.next === null;/);
});

test("the walk order is the SIGNED bundle order and nothing else", () => {
  assert.match(viewer, /bundleNeighbours\(bundleId, fileId\)/, "order comes from the retained BundleView");
  assert.match(viewer, /from "\.\/bundle-screen\.ts"/, "…imported from the screen that verified it");
  // Never re-derived from a listing, the local index, or a fresh open. Assert on
  // CODE, not prose: the method documents the rule in a comment that names
  // open_bundle, so strip line comments first.
  assert.doesNotMatch(
    viewer.replace(/^\s*\/\/.*$/gm, ""),
    /list_feed|search_local|open_bundle/,
    "the viewer must not re-derive member order from any other source",
  );
});

test("no verified order ⇒ no navigation is offered at all", () => {
  assert.match(
    viewer,
    /if \(around === null \|\| around\.total <= 1\) return;/,
    "a cold deep-link must leave the nav hidden rather than guess an order",
  );
});

test("the walk keeps the gallery on the page containing the open member", () => {
  assert.match(viewer, /rememberBundlePageFor\(bundleId, fileId\)/);
});

test("the embedded (Stacked) viewer grows no walk chrome", () => {
  const embedded = viewer.match(/if \(embedded\) \{[\s\S]*?\n    \} else \{/)?.[0];
  assert.ok(embedded, "the embedded branch must exist");
  assert.doesNotMatch(embedded, /vw-bundle-nav/, "an embedded viewer must not emit the walk nav");
  assert.match(
    viewer,
    /if \(this\.bundleId !== ""\) this\.renderBundleNav\(this\.bundleId, id\);/,
    "the walk is wired on the routed branch only",
  );
});

test("a member's verified version is remembered, and a bogus one is never sent", () => {
  assert.match(
    viewer,
    /rememberMemberVersion\(this\.bundleId, this\.reqId, c\.version\)/,
    "a successful open must record the version it verified",
  );
  assert.match(viewer, /function parseVersion/, "URL/attribute versions must be parsed defensively");
  assert.match(
    viewer,
    /Number\.isInteger\(n\) && n > 0 \? n : undefined/,
    "0, NaN and empty must all read as absent",
  );
});

// --- Issue 2: the bundle gallery reuses the feed's tile grid ------------------
const css = readFileSync("styles.css", "utf8");

test(".bundle-gallery is a tile grid matching the feed #grid", () => {
  // The gallery must lay <media-card>s out on the SAME auto-fit tile grid the
  // feed uses (repeat(auto-fit, minmax(min(100%, 280px), 1fr))), not block flow.
  assert.match(
    css,
    /\.bundle-gallery\s*\{[\s\S]*?display:\s*grid[\s\S]*?repeat\(auto-fit,\s*minmax\(min\(100%,\s*280px\),\s*1fr\)\)/,
    ".bundle-gallery must define the feed's auto-fit tile grid",
  );
});
