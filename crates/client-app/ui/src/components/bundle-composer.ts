import { call, on } from "../core/rpc.ts";
import { serial } from "../core/serial.ts";
import { setBusy, clearBusy } from "../core/busy.ts";
import { toast } from "../core/toast.ts";
import { reorderMember, removeMember, detectKind, basename, canBeginStage } from "../core/composer.ts";
import {
  normalizeOptions,
  resolutionForPreset,
  suggestKbps,
} from "../core/transcode-opts.ts";
import type { Bitrate, Resolution, TranscodeOptions } from "../core/transcode-opts.ts";
import type {
  BundleMemberInput,
  BundlePreview,
  BundleStagePhase,
  PreparePhase,
  StageBundleRequest,
  UploadPreview,
} from "../core/types.ts";

// Bundle composer (bundles feature, Task 4.1): a "New bundle" mode mounted by
// <upload-screen>. The author assembles an ORDERED list of members — media files
// (auto-typed image/video/generic from the extension) and inline text (blog) —
// gives each a title (+ per-video transcode shaping), reorders (▲/▼) / removes
// (✕) them, then Previews (stage_bundle — encrypts LOCALLY, NO network) in Gallery
// or Stacked mode and Posts (confirm_bundle — uploads, progress via the uploads
// tray). A stale staged bundle is cancelled (cancel_bundle) before re-staging so
// no orphaned staging dir leaks on disk.
//
// This component is NOT a routed screen: <upload-screen> owns the single #main
// landmark; the composer is a child region with its OWN aria-live status region.
//
// XSS note: the innerHTML skeleton below is FULLY STATIC. Every dynamic node
// (member rows, preview cells, status text) is built via createElement/textContent
// / setAttribute — never interpolated into innerHTML.
export class BundleComposer extends HTMLElement {
  // The ordered members being assembled — the single source of truth. Row inputs
  // write straight back into these objects (title/content/options) on edit, so a
  // re-render (after reorder/remove) always reflects the latest state.
  private members: BundleMemberInput[] = [];
  // The job_id of the most recent successful stage_bundle (null once posted /
  // cancelled / never staged). Used to Post and to cancel a stale staging dir.
  private lastJobId: string | null = null;
  private lastPreview: BundlePreview | null = null;
  // True whenever the member list/fields changed since the last successful stage,
  // so Preview/Post know to re-stage (and cancel the stale job first).
  private dirty = true;
  private previewMode: "gallery" | "stacked" = "gallery";
  // Single-flight guard: true while a stage_bundle is in flight. Blocks a second
  // concurrent stage (double-clicked Preview, or Gallery→Stacked in quick
  // succession) whose cancelStale() would run before the first stage set
  // lastJobId — which would orphan the first staged bundle's on-disk staging dir.
  // Covers BOTH preview() and post() since they share the stage/cancel/job_id state.
  private staging = false;

  // The member chosen as the bundle's cover — its thumbnail becomes the bundle's
  // own feed-card preview. Tracked by object REFERENCE so it survives reorder/remove
  // (both preserve member object identity). Only image members are cover-eligible;
  // ensureCover() keeps this valid (defaults to the first image member, or null).
  private coverMember: BundleMemberInput | null = null;

  // Nominal 16:9 dims per height preset — only a starting bitrate-suggestion source
  // (mirrors <upload-screen>). The Rust side re-clamps authoritatively.
  private static readonly PRESET_DIMS: Record<string, { w: number; h: number }> = {
    "2160": { w: 3840, h: 2160 },
    "1440": { w: 2560, h: 1440 },
    "1080": { w: 1920, h: 1080 },
    "720": { w: 1280, h: 720 },
    "480": { w: 854, h: 480 },
  };

  connectedCallback() {
    this.innerHTML = `
      <section id="bc-region" class="composer" tabindex="-1" aria-labelledby="bc-h">
        <h2 id="bc-h">New bundle</h2>
        <label>Bundle title <input id="bc-title" type="text" autocomplete="off" /></label>
        <label>Tags (comma-separated) <input id="bc-tags" type="text" autocomplete="off" /></label>
        <div class="bc-add" role="group" aria-label="Add bundle items">
          <button id="bc-add-media" type="button">Add media…</button>
          <button id="bc-add-text" type="button">Add text</button>
        </div>
        <ol id="bc-members" class="bc-members"></ol>
        <div class="bc-preview-toggle" role="group" aria-label="Preview mode">
          <button id="bc-prev-gallery" type="button">Preview gallery</button>
          <button id="bc-prev-stacked" type="button">Preview stacked</button>
        </div>
        <button id="bc-post" type="button" class="bc-post">Post bundle</button>
        <p id="bc-status" role="status" aria-live="polite"></p>
        <div id="bc-preview" class="bc-preview"></div>
      </section>`;
    (this.querySelector("#bc-region") as HTMLElement).focus();

    (this.querySelector("#bc-add-media") as HTMLButtonElement).addEventListener("click", () =>
      void this.onAddMedia(),
    );
    (this.querySelector("#bc-add-text") as HTMLButtonElement).addEventListener("click", () =>
      this.onAddText(),
    );
    (this.querySelector("#bc-prev-gallery") as HTMLButtonElement).addEventListener("click", () =>
      void this.preview("gallery"),
    );
    (this.querySelector("#bc-prev-stacked") as HTMLButtonElement).addEventListener("click", () =>
      void this.preview("stacked"),
    );
    const post = this.querySelector("#bc-post") as HTMLButtonElement;
    post.addEventListener("click", () => void this.post(post));
    // Title/tags edits invalidate any staged preview.
    for (const id of ["#bc-title", "#bc-tags"]) {
      (this.querySelector(id) as HTMLInputElement).addEventListener("input", () => this.markDirty());
    }

    this.renderMembers();
  }

  disconnectedCallback() {
    // Cancel any not-yet-posted staged bundle so no staging dir leaks on disk
    // when the composer is torn down (mode switch / navigation).
    this.cancelStale();
  }

  // --- Member list edits -----------------------------------------------------

  private async onAddMedia() {
    try {
      // Empty extensions ⇒ the dialog shows ALL files; detectKind classifies each
      // pick (image / video / generic). Multi-select: every chosen file is added.
      const paths = await call<string[]>("pick_files", { extensions: [] });
      if (!paths || paths.length === 0) return;
      const added = paths.map((path): BundleMemberInput => {
        const kind = detectKind(path);
        const member: BundleMemberInput = { kind, path, title: basename(path), tags: [] };
        if (kind === "video") member.options = { resolution: "Original", bitrate: "Original" };
        return member;
      });
      this.members = [...this.members, ...added];
      this.markDirty();
      this.renderMembers();
    } catch (x) {
      this.status(errMsg(x, "Could not open the file dialog."));
    }
  }

  private onAddText() {
    const n = this.members.filter((m) => m.kind === "blog").length + 1;
    this.members = [...this.members, { kind: "blog", content: "", title: `Text ${n}`, tags: [] }];
    this.markDirty();
    this.renderMembers();
  }

  private markDirty() {
    this.dirty = true;
  }

  // Cancel + forget the current staged bundle (best-effort; idempotent server-side).
  private cancelStale() {
    if (this.lastJobId) {
      const stale = this.lastJobId;
      this.lastJobId = null;
      this.lastPreview = null;
      void call("cancel_bundle", { req: { job_id: stale } }).catch(() => {});
    }
  }

  // --- Rendering the editable member rows ------------------------------------

  private renderMembers() {
    const list = this.querySelector("#bc-members") as HTMLElement;
    list.replaceChildren();
    if (this.members.length === 0) {
      const empty = document.createElement("li");
      empty.className = "bc-empty";
      empty.textContent = "No items yet — add media or text to build your bundle.";
      list.appendChild(empty);
      return;
    }
    this.ensureCover();
    this.members.forEach((m, i) => list.appendChild(this.buildRow(m, i)));
  }

  // A member eligible to be the bundle cover: one that yields a thumbnail — an
  // image OR a video (whose poster frame is its thumbnail). Blog/generic members
  // have no thumbnail, so they can't be the cover.
  private coverEligible(m: BundleMemberInput): boolean {
    return m.kind === "image" || m.kind === "video";
  }

  // Keep `coverMember` valid: if unset or no longer a present cover-eligible member,
  // default to the first eligible member (or null when the bundle has none). Called
  // on every render so reorder/remove/add can't leave a dangling cover reference.
  private ensureCover() {
    const eligible = this.members.filter((m) => this.coverEligible(m));
    if (!this.coverMember || !eligible.includes(this.coverMember)) {
      this.coverMember = eligible[0] ?? null;
    }
  }

  private buildRow(m: BundleMemberInput, i: number): HTMLElement {
    const row = document.createElement("li");
    row.className = "bc-row";

    const head = document.createElement("div");
    head.className = "bc-row-head";
    const badge = document.createElement("span");
    badge.className = "bc-kind";
    badge.textContent = kindLabel(m.kind);
    head.appendChild(badge);

    // Reorder / remove controls — real, keyboard-operable <button>s with names.
    const controls = document.createElement("div");
    controls.className = "bc-row-controls";
    const up = this.iconButton("▲", `Move item ${i + 1} up`, i === 0, () => {
      this.members = reorderMember(this.members, i, "up");
      this.markDirty();
      this.renderMembers();
    });
    const down = this.iconButton("▼", `Move item ${i + 1} down`, i === this.members.length - 1, () => {
      this.members = reorderMember(this.members, i, "down");
      this.markDirty();
      this.renderMembers();
    });
    const rm = this.iconButton("✕", `Remove item ${i + 1}`, false, () => {
      this.members = removeMember(this.members, i);
      this.markDirty();
      this.renderMembers();
    });
    controls.append(up, down, rm);
    head.appendChild(controls);
    row.appendChild(head);

    // Per-member title.
    const titleLabel = document.createElement("label");
    titleLabel.className = "bc-title-label";
    titleLabel.append(document.createTextNode("Title "));
    const title = document.createElement("input");
    title.type = "text";
    title.autocomplete = "off";
    title.value = m.title;
    title.addEventListener("input", () => {
      m.title = title.value;
      this.markDirty();
    });
    titleLabel.appendChild(title);
    row.appendChild(titleLabel);

    if (m.kind === "blog") {
      const bodyLabel = document.createElement("label");
      bodyLabel.className = "bc-body-label";
      bodyLabel.append(document.createTextNode("Text "));
      const ta = document.createElement("textarea");
      ta.rows = 4;
      ta.value = m.content ?? "";
      ta.addEventListener("input", () => {
        m.content = ta.value;
        this.markDirty();
      });
      bodyLabel.appendChild(ta);
      row.appendChild(bodyLabel);
    } else {
      // image / video / generic: show the picked source filename (read-only).
      const src = document.createElement("p");
      src.className = "bc-src";
      src.textContent = m.path ? basename(m.path) : "";
      row.appendChild(src);
      if (this.coverEligible(m)) row.appendChild(this.buildCoverToggle(m));
      if (m.kind === "video") row.appendChild(this.buildVideoOpts(m));
    }
    return row;
  }

  // A radio marking THIS image member as the bundle's cover (its thumbnail becomes
  // the bundle's feed-card preview). Single-select across image members via the
  // shared radio-group name, so picking one deselects the rest on the next render.
  private buildCoverToggle(m: BundleMemberInput): HTMLElement {
    const label = document.createElement("label");
    label.className = "bc-cover";
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "bc-cover";
    radio.checked = m === this.coverMember;
    radio.addEventListener("change", () => {
      this.coverMember = m;
      this.markDirty();
      this.renderMembers();
    });
    label.append(radio, document.createTextNode(" Use as bundle cover"));
    return label;
  }

  // A real, labelled, keyboard-operable icon button.
  private iconButton(glyph: string, label: string, disabled: boolean, onClick: () => void): HTMLButtonElement {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "bc-icon-btn";
    b.textContent = glyph;
    b.setAttribute("aria-label", label);
    b.disabled = disabled;
    b.addEventListener("click", onClick);
    return b;
  }

  // Per-video transcode shaping: a resolution preset select + a bitrate override
  // (default "Original bitrate"). Reuses core/transcode-opts.ts exactly (the JSON
  // shape mirrors the Rust TranscodeOptions; the Rust side always re-clamps).
  private buildVideoOpts(m: BundleMemberInput): HTMLElement {
    const wrap = document.createElement("div");
    wrap.className = "bc-vopts";

    const resLabel = document.createElement("label");
    resLabel.append(document.createTextNode("Resolution "));
    const res = document.createElement("select");
    for (const [v, t] of [
      ["original", "Original (keep source)"],
      ["2160", "2160p (4K)"],
      ["1440", "1440p (QHD)"],
      ["1080", "1080p (Full HD)"],
      ["720", "720p (HD)"],
      ["480", "480p (SD)"],
    ] as const) {
      const o = document.createElement("option");
      o.value = v;
      o.textContent = t;
      res.appendChild(o);
    }
    resLabel.appendChild(res);

    const kbpsLabel = document.createElement("label");
    kbpsLabel.append(document.createTextNode("Bitrate (kbps) "));
    const kbps = document.createElement("input");
    kbps.type = "number";
    kbps.min = "64";
    kbps.max = "200000";
    kbps.step = "1";
    kbps.autocomplete = "off";
    kbpsLabel.appendChild(kbps);

    const origLabel = document.createElement("label");
    const orig = document.createElement("input");
    orig.type = "checkbox";
    orig.checked = true;
    origLabel.append(orig, document.createTextNode(" Original bitrate"));

    const recompute = () => {
      const resolution: Resolution = res.value === "original" ? "Original" : resolutionForPreset(res.value);
      const bitrate: Bitrate = orig.checked ? "Original" : { Kbps: Number(kbps.value) };
      m.options = normalizeOptions({ resolution, bitrate } as TranscodeOptions);
      this.markDirty();
    };
    res.addEventListener("change", () => {
      // Moving off Original suggests a starting bitrate (from the target preset's
      // nominal dims at 30 fps) and unchecks Original bitrate so it is editable.
      if (res.value !== "original") {
        const dims = BundleComposer.PRESET_DIMS[res.value];
        if (dims && orig.checked) {
          kbps.value = String(suggestKbps(dims.w, dims.h, 30));
          orig.checked = false;
        }
      } else {
        orig.checked = true; // Original resolution ⇒ keep source bitrate.
      }
      recompute();
    });
    kbps.addEventListener("input", () => {
      orig.checked = false;
      recompute();
    });
    orig.addEventListener("change", recompute);

    wrap.append(resLabel, kbpsLabel, origLabel);
    return wrap;
  }

  // --- Preview + Post --------------------------------------------------------

  private buildRequest(): StageBundleRequest {
    const title = (this.querySelector("#bc-title") as HTMLInputElement).value.trim();
    const tags = splitTags((this.querySelector("#bc-tags") as HTMLInputElement).value);
    const members: BundleMemberInput[] = this.members.map((m) => {
      const out: BundleMemberInput = {
        kind: m.kind,
        title: m.title.trim() || "(untitled)",
        tags: m.tags,
      };
      if (m.kind === "blog") {
        out.content = m.content ?? "";
      } else {
        out.path = m.path;
        if (m.kind === "video" && m.options) out.options = m.options;
      }
      return out;
    });
    const req: StageBundleRequest = { title, tags, members };
    // Cover: the chosen image member's position (1:1 with `members` above, since the
    // map preserves order). Only an image member is cover-eligible (yields a thumb).
    const coverIdx = this.coverMember ? this.members.indexOf(this.coverMember) : -1;
    if (coverIdx >= 0 && this.coverEligible(this.members[coverIdx])) req.cover_index = coverIdx;
    return req;
  }

  // Stage (if needed) and render the member previews in the chosen mode. A fresh
  // (non-dirty) preview just re-renders in the new mode with NO network call.
  private async preview(mode: "gallery" | "stacked") {
    // Single-flight: refuse a re-entrant stage while one is already running.
    if (!canBeginStage(this.staging)) return;
    this.previewMode = mode;
    this.syncPreviewToggle();
    if (this.members.length === 0) {
      this.status("Add at least one item first.");
      return;
    }
    if (!this.dirty && this.lastPreview) {
      this.renderPreview(this.lastPreview);
      return;
    }
    this.setStagingBusy(true);
    this.status("Preparing preview…");
    // Cancel any stale staged bundle BEFORE re-staging (no orphaned staging dir).
    // The single-flight guard guarantees no other stage is mid-flight here, so
    // lastJobId (if any) is the one to cancel.
    this.cancelStale();
    setBusy("Preparing bundle");
    try {
      const preview = await this.stageWithProgress("Preparing preview");
      this.lastJobId = preview.job_id;
      this.lastPreview = preview;
      this.dirty = false;
      this.renderPreview(preview);
      this.status("Preview ready — review, then Post bundle.");
    } catch (x) {
      this.status(errMsg(x, "Could not prepare the bundle preview."));
    } finally {
      clearBusy();
      this.setStagingBusy(false);
    }
  }

  // Toggle the single-flight state + disable/enable the Preview + Post buttons so
  // the user cannot fire a second stage while one is in flight.
  private setStagingBusy(on: boolean) {
    this.staging = on;
    for (const id of ["#bc-prev-gallery", "#bc-prev-stacked", "#bc-post"]) {
      const b = this.querySelector(id) as HTMLButtonElement | null;
      if (b) b.disabled = on;
    }
  }

  private syncPreviewToggle() {
    const g = this.querySelector("#bc-prev-gallery") as HTMLButtonElement;
    const s = this.querySelector("#bc-prev-stacked") as HTMLButtonElement;
    g.setAttribute("aria-pressed", String(this.previewMode === "gallery"));
    s.setAttribute("aria-pressed", String(this.previewMode === "stacked"));
    g.classList.toggle("active", this.previewMode === "gallery");
    s.classList.toggle("active", this.previewMode === "stacked");
  }

  // Render the staged member previews (title/thumbnail/type from member_previews)
  // in Gallery (a grid of cells) or Stacked (a vertical list) form + the counts.
  private renderPreview(p: BundlePreview) {
    const wrap = this.querySelector("#bc-preview") as HTMLElement;
    wrap.replaceChildren();

    const counts = document.createElement("p");
    counts.className = "bc-counts";
    const c = p.counts;
    counts.textContent =
      `${p.member_previews.length} item${p.member_previews.length === 1 ? "" : "s"} — ` +
      `${c.image} image, ${c.video} video, ${c.blog} text, ${c.generic} file.`;
    wrap.appendChild(counts);

    const container = document.createElement("div");
    container.setAttribute("role", "list");
    container.className = this.previewMode === "gallery" ? "bc-preview-gallery" : "bc-preview-stack";
    for (const mp of p.member_previews) container.appendChild(this.buildPreviewCell(mp));
    wrap.appendChild(container);
  }

  private buildPreviewCell(mp: UploadPreview): HTMLElement {
    const cell = document.createElement("div");
    cell.className = this.previewMode === "gallery" ? "bc-cell bc-cell-gallery" : "bc-cell bc-cell-stack";
    cell.setAttribute("role", "listitem");
    if (mp.thumbnail_b64) {
      const img = document.createElement("img");
      // createElement + .src (NOT innerHTML) — safe; the a11y XSS lint targets
      // only unescaped `${…}` inside an innerHTML template literal.
      img.src = `data:image/png;base64,${mp.thumbnail_b64}`;
      img.alt = mp.title ? `Thumbnail: ${mp.title}` : "Thumbnail";
      cell.appendChild(img);
    }
    const t = document.createElement("p");
    t.className = "bc-cell-title";
    t.textContent = mp.title || "(untitled)";
    const ty = document.createElement("p");
    ty.className = "bc-cell-type";
    ty.textContent = mp.file_type;
    cell.append(t, ty);
    return cell;
  }

  private async post(_btn: HTMLButtonElement) {
    // Single-flight: post shares the stage/cancel/job_id state with preview, so
    // the same guard blocks a Post firing a stage concurrently with a Preview.
    if (!canBeginStage(this.staging)) return;
    if (this.members.length === 0) {
      this.status("Add at least one item first.");
      return;
    }
    this.setStagingBusy(true);
    setBusy("Posting bundle");
    try {
      // Ensure a fresh staged job: (re)stage if never previewed or edited since.
      if (this.dirty || !this.lastJobId) {
        this.cancelStale();
        const preview = await this.stageWithProgress("Preparing bundle");
        this.lastJobId = preview.job_id;
        this.lastPreview = preview;
        this.dirty = false;
      }
      const jobId = this.lastJobId as string;
      this.status("Posting… (see the uploads tray)");
      // confirm_bundle re-auths per call — route through the shared serial queue.
      await serial(() => call<string>("confirm_bundle", { req: { job_id: jobId } }));
      this.reset();
      toast("success", "Bundle posted.");
      this.status("Bundle posted.");
    } catch (x) {
      this.status(errMsg(x, "Could not post the bundle."));
    } finally {
      clearBusy();
      this.setStagingBusy(false);
    }
  }

  private reset() {
    this.members = [];
    this.lastJobId = null;
    this.lastPreview = null;
    this.dirty = true;
    (this.querySelector("#bc-title") as HTMLInputElement).value = "";
    (this.querySelector("#bc-tags") as HTMLInputElement).value = "";
    (this.querySelector("#bc-preview") as HTMLElement).replaceChildren();
    this.renderMembers();
  }

  private status(msg: string) {
    (this.querySelector("#bc-status") as HTMLElement).textContent = msg;
  }

  // Run `stage_bundle` while streaming live progress into the status line: which
  // member (index/total) is being prepared and, for a video member, its transcode
  // percent. `label` is the leading verb ("Preparing preview", "Preparing
  // bundle"). Subscriptions are set up before the call and always torn down after,
  // even on error. The single-flight guard guarantees this is the only stage in
  // flight, so the events we hear belong to this call.
  private async stageWithProgress(label: string): Promise<BundlePreview> {
    let line = ""; // "— item 2/5: My Video"
    let detail = ""; // " (transcoding 42%)"
    const render = () => this.status(`${label}${line ? " " + line : "…"}${detail}`);
    render();
    const unlisten: Array<() => void> = [];
    try {
      unlisten.push(
        await on<BundleStagePhase>("maxsecu://bundle-stage", (p) => {
          line = `— item ${p.index}/${p.total}: ${p.title || "(untitled)"}`;
          detail = ""; // reset per-member video detail
          render();
        }),
      );
      unlisten.push(
        await on<PreparePhase>("maxsecu://video-prepare", (p) => {
          if (p.phase === "transcoding") {
            detail = ` (transcoding ${p.percent == null ? "…" : p.percent + "%"})`;
          } else if (p.phase === "remuxing") {
            detail = " (finishing video…)";
          } else {
            detail = "";
          }
          render();
        }),
      );
      return await call<BundlePreview>("stage_bundle", { req: this.buildRequest() });
    } finally {
      for (const u of unlisten) u();
    }
  }
}

function kindLabel(kind: string): string {
  switch (kind) {
    case "image":
      return "Image";
    case "video":
      return "Video";
    case "blog":
      return "Text";
    default:
      return "File";
  }
}

function splitTags(raw: string): string[] {
  return raw
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

function errMsg(x: unknown, fallback: string): string {
  if (x && typeof x === "object" && "message" in x) {
    const m = (x as { message?: unknown }).message;
    if (typeof m === "string") return m;
  }
  return fallback;
}

customElements.define("bundle-composer", BundleComposer);
