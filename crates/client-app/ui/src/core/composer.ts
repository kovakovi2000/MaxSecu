// Pure member-list helpers for the bundle composer (bundles feature, Task 4.1).
// NO DOM, NO Tauri, NO side effects — just array transforms + extension mapping,
// so they unit-test without a browser (the node harness has neither a DOM nor the
// Tauri API). The <bundle-composer> component drives its `members` state through
// these; keeping them here (mirroring core/card-retry.ts / core/bundle-view.ts)
// keeps the Tauri-importing component out of the node test path.

// The kind a picked media file maps to. Blog members are added via "Add text",
// never auto-detected from a file, so detectKind never returns "blog".
export type MediaKind = "image" | "video" | "generic";

// Extensions (lowercase, no dot) that map to each media kind. Anything not listed
// falls through to "generic" (still a REAL bundle member — download-only).
const IMAGE_EXT = new Set(["png", "jpg", "jpeg", "webp", "gif", "bmp", "avif", "tiff", "tif"]);
const VIDEO_EXT = new Set([
  "mp4", "mov", "mkv", "webm", "avi", "m4v", "mpg", "mpeg", "wmv", "flv", "ts", "3gp", "ogv",
]);

/**
 * Auto-detect a bundle member's kind from a filename/path by its extension:
 * image extensions → "image", video extensions → "video", anything else
 * (including no extension) → "generic". Case-insensitive; accepts a bare
 * filename or a full path (splits on both "/" and "\").
 */
export function detectKind(filename: string): MediaKind {
  const base = filename.split(/[\\/]/).pop() ?? "";
  const dot = base.lastIndexOf(".");
  const ext = dot > 0 ? base.slice(dot + 1).toLowerCase() : "";
  if (IMAGE_EXT.has(ext)) return "image";
  if (VIDEO_EXT.has(ext)) return "video";
  return "generic";
}

/**
 * Move the member at `index` one slot up or down, returning a NEW array. A no-op
 * (returns a fresh copy of the input, unchanged) when the move would fall off
 * either end or `index` is out of range — so it is safe to wire straight to the
 * ▲/▼ buttons of the first/last rows.
 */
export function reorderMember<T>(list: T[], index: number, dir: "up" | "down"): T[] {
  const out = list.slice();
  const target = dir === "up" ? index - 1 : index + 1;
  if (index < 0 || index >= out.length || target < 0 || target >= out.length) return out;
  const tmp = out[index];
  out[index] = out[target];
  out[target] = tmp;
  return out;
}

/**
 * Remove the member at `index`, returning a NEW array. An out-of-range index is a
 * no-op (returns a fresh copy of the input, unchanged).
 */
export function removeMember<T>(list: T[], index: number): T[] {
  const out = list.slice();
  if (index < 0 || index >= out.length) return out;
  out.splice(index, 1);
  return out;
}

/**
 * Single-flight gate for the composer's stage/confirm state machine. Returns true
 * only when NO stage_bundle is currently in flight, so `preview()`/`post()` can
 * begin. While a stage is running, `staging` is true and this returns false —
 * blocking a second concurrent `stage_bundle` (a double-click, or Gallery→Stacked
 * in quick succession) whose `cancelStale()` would run before the first stage set
 * `lastJobId`, orphaning the first staged bundle's on-disk staging dir.
 */
export function canBeginStage(staging: boolean): boolean {
  return !staging;
}

/**
 * The trailing path segment (basename) of a full path, splitting on both "/" and
 * "\". Used to seed a member's default title from the picked filename. Returns the
 * input unchanged when there is no separator.
 */
export function basename(path: string): string {
  const seg = path.split(/[\\/]/).pop() ?? path;
  return seg.length > 0 ? seg : path;
}
