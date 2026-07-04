// Pure, DOM-free filename helpers for the Download / Download-all flows (Task 5.2).
// `downloadName` builds a save-as suggestion from a post's type + title; `dedupeName`
// disambiguates colliding names within a Download-all batch. Neither imports Tauri or
// touches the DOM, so both are unit-testable in the node harness (download-name.test.ts).
//
// This only PRE-FILLS a suggested name — the real path-safety boundary is the OS
// "save as" dialog / the caller-provided folder that `download_content` writes into
// (mirrors the Rust `suggested_filename`/`sanitize_name` contract).

const EXT: Record<string, string> = { image: "png", video: "mp4", blog: "txt" };

/// Suggested save-as filename for a post: image→`<title>.png`, video→`<title>.mp4`,
/// blog→`<title>.txt`. For a generic file the title IS the filename (kept as-is, no
/// forced extension). Any unknown type is treated like generic. When the (sanitized)
/// title is empty, fall back to a safe neutral default per kind.
export function downloadName(fileType: string, title: string): string {
  const clean = sanitizeName(title);
  const ext = EXT[fileType];
  if (ext) return clean === "" ? `download.${ext}` : `${clean}.${ext}`;
  // generic + unknown: the title is the filename; neutral binary default when blank.
  return clean === "" ? "download.bin" : clean;
}

/// Return `name` if unused, else the first free `<base> (N)<.ext>` (N ≥ 2), inserting
/// the suffix BEFORE the extension so `a.png` → `a (2).png`. The chosen name is added
/// to `used` so a subsequent call sees it as taken.
export function dedupeName(name: string, used: Set<string>): string {
  let candidate = name;
  if (used.has(candidate)) {
    const dot = name.lastIndexOf(".");
    const base = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : "";
    let i = 2;
    do {
      candidate = `${base} (${i})${ext}`;
      i++;
    } while (used.has(candidate));
  }
  used.add(candidate);
  return candidate;
}

/// Strip anything that could make the name path-traversing / illegal (path
/// separators, drive/stream colons, Windows-reserved glob chars, control chars),
/// then trim surrounding whitespace and dots (so it can never be `.`/`..`/a dotfile).
/// Interior extension dots survive. Mirrors the Rust `sanitize_name`.
function sanitizeName(raw: string): string {
  const cleaned = Array.from(raw)
    .filter((c) => {
      const code = c.codePointAt(0)!;
      const isControl = code < 0x20 || code === 0x7f;
      return !isControl && !'/\\:*?"<>|'.includes(c);
    })
    .join("");
  return cleaned.replace(/^[\s.]+/, "").replace(/[\s.]+$/, "");
}
