// Pure, DOM-free view helpers for <media-card>. The component itself imports the
// Tauri API (via core/rpc.ts) and cannot mount in the node test harness, so the
// pure bits it renders from live here and are unit-tested directly (mirrors the
// card-retry.ts / bundle-view.ts convention).

/** The counts of a bundle's members by kind — mirrors the Rust `MemberCounts`. */
export interface MemberCounts {
  video: number;
  image: number;
  blog: number;
  generic: number;
}

// The route a feed card links to. A bundle card opens the bundle screen
// (#/bundle?id=…); every other kind opens the viewer (#/viewer?id=…[&v=…]).
export interface CardReturnTarget {
  route?: "feed" | "mine";
  bundleId?: string;
}

export function cardHref(file_type: string, id: string, version?: number, from?: CardReturnTarget): string {
  const parts = [`id=${encodeURIComponent(id)}`];
  if (file_type !== "bundle" && version !== undefined) parts.push(`v=${encodeURIComponent(String(version))}`);
  if (from?.bundleId) {
    parts.push("from=bundle", `bundle=${encodeURIComponent(from.bundleId)}`);
  } else if (from?.route === "mine") {
    parts.push("from=mine");
  } else if (from?.route === "feed") {
    parts.push("from=feed");
  }
  return file_type === "bundle" ? `#/bundle?${parts.join("&")}` : `#/viewer?${parts.join("&")}`;
}

// A compact "VID 1 · IMG 4 · TXT 1 · FILE 0" strip for a bundle's member tally,
// omitting zero categories so an image-only bundle reads "IMG 4" not a wall of
// zeros. TXT = blog, FILE = generic. Returns "" when every category is zero (the
// caller then omits the strip entirely).
export function countsLabel(mc: MemberCounts): string {
  const parts: string[] = [];
  if (mc.video) parts.push(`VID ${mc.video}`);
  if (mc.image) parts.push(`IMG ${mc.image}`);
  if (mc.blog) parts.push(`TXT ${mc.blog}`);
  if (mc.generic) parts.push(`FILE ${mc.generic}`);
  return parts.join(" · ");
}
