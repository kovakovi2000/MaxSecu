import type { TranscodeOptions } from "./transcode-opts.ts";

export interface ConnState { state: string }
export interface AuthStateMsg { state: string }
export interface MintedKeyResponse { registration_key: string }

// --- Trusted-server recovery login (spec §6) DTO mirrors ---
// No key material ever crosses the seam: only an opaque status + the public
// server_id. The cold recovery private key + the challenge nonce stay in Rust.
export interface RecoveryChallengeDto { status: string; server_id: string }
export interface RecoveryLoginDto { status: string; server_id: string }

// --- Registration-key enrollment (spec §5) DTO mirror ---
// The single-use key is read from the local register.key file in Rust, never on
// the seam. Only the enrolled username + the opaque server-assigned user_id return.
export interface RegisteredDto { username: string; user_id: string }

// --- Phase 3 (browse + view) DTO mirrors of the Rust serde shapes ---
// kebab-case enum values, snake_case fields — match server/core serde exactly.
export type FeedFilter = "all" | "image" | "video" | "blog";
export type FeedSort = "newest-first" | "oldest-first";

export interface FeedEntry {
  file_id: string;
  file_type: string;
  version: number;
  updated_at: number;
  has_thumbnail: boolean;
}

export interface Card {
  file_id: string;
  file_type: string;
  version: number;
  title: string;
  tags: string[];
  thumbnail_b64: string | null;
  mine: boolean;
  author_fp: string;
  recovery_ok: boolean;
  // For a bundle card: how many members of each kind it groups (counts only,
  // never member order). Always present — zeros for a non-bundle card.
  member_counts: { video: number; image: number; blog: number; generic: number };
}

export interface OpenedContent {
  file_id: string;
  file_type: string;
  version: number;
  title: string;
  tags: string[];
  image_png_b64: string | null;
  blog_text: string | null;
  author_fp: string;
  recovery_ok: boolean;
  // T4 (D-OQ3): true whenever the open succeeded, i.e. the caller holds a wrap
  // for this item — NOT ownership-gated. Gates the viewer's "Share…" action.
  can_share: boolean;
  // Bundles Task 6.2: true iff THIS user authored the item — gates the
  // owner-only permanent-Delete action (distinct from can_share).
  mine: boolean;
}

// --- T4 (post-upload multi-recipient sharing) DTO mirrors ---

// A resolved potential share recipient — display-only, no key material.
export interface ResolvedRecipient {
  username: string;
  user_id: string; // hex16, opaque to the UI
  fingerprint: string; // first 8 bytes hex, display-only
  already_shared: boolean;
}

// A known contact (roster row) for the share checklist — mirrors ContactDto.
export interface Contact {
  username: string;
  user_id: string; // hex16, opaque to the UI
  fingerprint: string; // first 8 bytes hex, display-only
}

// The per-recipient outcome of a reshare_file call, in request order.
export interface ReshareOutcome {
  username: string;
  ok: boolean;
  code: string | null; // sanitized failure code, null on success
}

// The background reshare feedback channel (T4 spec §6), emitted over
// maxsecu://reshare-state. kebab-tagged on "phase"; mirrors the Rust
// `SharePhase` serde shape exactly. No key material — file_id/username/
// ok/code/counts only.
export type SharePhase =
  | { phase: "resolving"; file_id: string; username: string }
  | { phase: "verifying"; file_id: string; username: string }
  | { phase: "wrapping"; file_id: string; username: string }
  | { phase: "recipient"; file_id: string; username: string; ok: boolean; code: string | null }
  | { phase: "done"; file_id: string; shared: number; failed: number };

export interface SearchHit { file_id: string; title: string; file_type: string }

// --- Bundles DTO mirrors (open_bundle) ---
// A bundle is a grouped post whose members are other posts, viewed in Gallery or
// Stacked mode. Mirrors the Rust serde shapes; display-only, no key material.
export interface BundleMemberView {
  file_id: string;
  file_type: string;
  title: string;
  thumbnail_b64: string | null;
}

export interface BundleView {
  file_id: string;
  file_type: string;
  version: number;
  members: BundleMemberView[];
  // Bundles Task 6.2: true iff THIS user authored the bundle — gates the
  // owner-only "Delete bundle" action (server cascades member deletion).
  mine: boolean;
}

export type FetchMsg =
  | { phase: "fetching"; file_id: string; fetched: number; total: number }
  | { phase: "verifying"; file_id: string }
  | { phase: "decrypting"; file_id: string }
  | { phase: "ready"; file_id: string }
  | { phase: "failed"; file_id: string; code: string };

// --- Phase 4 (upload) DTO mirrors of the Rust serde shapes ---
// Mirrors the Rust `UploadKind` enum (serde kebab-case). "generic" is the
// download-only bundle-member kind (no in-app view); the single-post form only
// exposes image/blog/video, but a bundle member may be generic.
export type UploadKind = "image" | "blog" | "video" | "generic";

export interface UploadPreview {
  job_id: string;
  file_type: string;
  title: string;
  tags: string[];
  byte_size: number;
  total_chunks: number;
  thumbnail_b64: string | null;
}

// --- Bundle composer (Task 4.1) DTO mirrors of the Rust serde shapes ---
// Order-private tally of a bundle's members by kind (mirrors Rust MemberCounts).
export interface MemberCounts { video: number; image: number; blog: number; generic: number }

// One member of a bundle being staged (mirrors Rust BundleMemberInput). Plain
// data only — no key material. `path` for image/video/generic; `content` for a
// blog; `options` shapes a video transcode. `title`/`tags` are per-member.
export interface BundleMemberInput {
  kind: UploadKind;
  path?: string;
  content?: string;
  options?: TranscodeOptions;
  title: string;
  tags: string[];
}

// A request to stage (not yet upload) a bundle: its own title/tags + ordered
// members (mirrors Rust StageBundleRequest). The member ORDER is authoritative.
export interface StageBundleRequest {
  title: string;
  tags: string[];
  members: BundleMemberInput[];
  // Index (into `members`) of the member whose thumbnail becomes the bundle's own
  // cover/index preview on its feed card. Must point at an image member; omitted ⇒
  // no cover. Mirrors Rust `StageBundleRequest.cover_index`.
  cover_index?: number;
}

// A preview of a staged-but-not-uploaded bundle (mirrors Rust BundlePreview): a
// per-member UploadPreview list + the order-private counts tally. No key material.
export interface BundlePreview {
  job_id: string;
  member_previews: UploadPreview[];
  counts: MemberCounts;
}

export type UploadMsg =
  | { phase: "encrypting"; job_id: string }
  | { phase: "staging"; job_id: string }
  | { phase: "uploading"; job_id: string; done: number; total: number; bytes_per_s: number }
  | { phase: "finalizing"; job_id: string }
  | { phase: "done"; job_id: string; file_id: string }
  | { phase: "failed"; job_id: string; code: string };

// Returned by list_pending_uploads() — one entry per interrupted upload that is
// still within the 24-hour retention window.
export interface PendingUploadView {
  file_id_hex: string;
  title: string;
  progress: number;
  total: number;
}

// --- Universal video ingest: transcode lifecycle events (maxsecu://video-prepare) ---
// kebab-tagged on "phase". `transcoding.percent` is null (indeterminate) until
// ffmpeg reports the source Duration; `cancelled` is a benign terminal; `failed`
// carries a sanitized code. Mirrors the Rust `PreparePhase` serde shape.
export type PreparePhase =
  | { phase: "transcoding"; percent: number | null }
  | { phase: "remuxing" }
  | { phase: "finalizing" }
  // The post-transcode "Preparing preview" encrypt/digest pass (streams the whole
  // prepared file through AES-GCM). `percent` is null until the first chunk seals.
  | { phase: "sealing"; percent: number | null }
  | { phase: "cancelled" }
  | { phase: "failed"; code: string };

// --- Bundle composer staging progress (maxsecu://bundle-stage) ---
// Emitted once per member as `stage_bundle` prepares them sequentially. `index`
// and `total` are 1-based; `title` is the member's (non-secret) title. Mirrors
// the Rust `BundleStagePhase` serde shape.
export type BundleStagePhase = { phase: "member"; index: number; total: number; title: string };

// --- Phase 5 (settings + a11y) DTO mirror of the Rust SettingsConfig serde shape ---
// Section objects, snake_case fields — match server/core serde exactly.
// The 3-way download/transport route (mirrors Rust `RouteMode`, serde kebab-case).
export type RouteMode = "tor-only" | "prefer-server" | "prefer-dropbox";
export interface Settings {
  a11y: { reduced_motion: boolean; high_contrast: boolean; text_size: "normal" | "large" | "larger" };
  behavior: { confirm_destructive: boolean };
  // `feed_concurrency` sizes the frontend decode pool (core/pool.ts): how many
  // feed cards decode in parallel. Backend-clamped 1..=8. `transcode_threads`
  // and `decode_threads` are the confined author-side / decode worker budgets
  // (Rust PerformanceSettings), clamped 1..=logical-CPUs. All three round-trip
  // through get_settings/set_settings; the backend re-clamps on save.
  performance: {
    // Two app-global ciphertext-in-RAM cache caps (MB). Media = video fragments +
    // full-content bytes; Thumbnails = feed-card meta/thumbnails. Each is the
    // denominator of its header gauge in Memory mode.
    media_cache_cap_mb: number;
    thumb_cache_cap_mb: number;
    feed_concurrency: number;
    transcode_threads: number;
    decode_threads: number;
    // Where both caches live. "Memory" (default) keeps ciphertext in RAM only;
    // "Disk" spills ciphertext to a temp dir (no cap, wiped on start + exit).
    // Mirrors Rust `CacheLocation` (serde bare string "Disk"/"Memory").
    cache_location: "Disk" | "Memory";
  };
  connection: { route_mode: RouteMode };
  appearance: { theme: "dark" | "light" };
}

// The RAM-cache slider/number bounds from the `ram_limits` command (Task 1).
export interface RamLimits { default_mb: number; min_mb: number; max_mb: number }

// Live process + budget memory figures from the `memory_stats` command.
// `used_bytes` is null when the OS process-RSS query is unavailable (fail-soft).
export interface MemoryStats { used_bytes: number | null; budget_bytes: number }

// Dual-mode cache footprint from the `cache_stats` command (takes the two live
// caps: `{ mediaCapBytes, thumbCapBytes }`). `media_used`/`thumb_used` are the
// bytes each app-global cache holds right now. In Memory mode (`disk_mode` false)
// the header gauges divide each by its configured cap; in Disk mode (`disk_mode`
// true) they divide the on-disk size by `disk_free_estimate` (the startup
// free-space probe, 0 in RAM mode or when the probe failed → raw-size fallback).
export interface CacheStats {
  media_used: number;
  thumb_used: number;
  disk_mode: boolean;
  disk_free_estimate: number;
}
