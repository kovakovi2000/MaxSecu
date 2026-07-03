export interface ConnState { state: string }
export interface AuthStateMsg { state: string }
export interface GlassbreakResponse { username: string; password: string; user_id: string }
export interface PendingUserDto { user_id: string; username: string; created_at: number }
export interface IssueVoucherResponse { code: string }
export interface AccountStateMsg { state: "unknown" | "pending" | "active" }

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
}

// --- T4 (post-upload multi-recipient sharing) DTO mirrors ---

// A resolved potential share recipient — display-only, no key material.
export interface ResolvedRecipient {
  username: string;
  user_id: string; // hex16, opaque to the UI
  fingerprint: string; // first 8 bytes hex, display-only
  already_shared: boolean;
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

export type FetchMsg =
  | { phase: "fetching"; file_id: string; fetched: number; total: number }
  | { phase: "verifying"; file_id: string }
  | { phase: "decrypting"; file_id: string }
  | { phase: "ready"; file_id: string }
  | { phase: "failed"; file_id: string; code: string };

// --- Phase 4 (upload) DTO mirrors of the Rust serde shapes ---
export type UploadKind = "image" | "blog" | "video";

export interface UploadPreview {
  job_id: string;
  file_type: string;
  title: string;
  tags: string[];
  byte_size: number;
  total_chunks: number;
  thumbnail_b64: string | null;
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
  | { phase: "cancelled" }
  | { phase: "failed"; code: string };

// --- Phase 5 (settings + a11y) DTO mirror of the Rust SettingsConfig serde shape ---
// Section objects, snake_case fields — match server/core serde exactly.
// The 3-way download/transport route (mirrors Rust `RouteMode`, serde kebab-case).
export type RouteMode = "tor-only" | "prefer-server" | "prefer-dropbox";
export interface Settings {
  a11y: { reduced_motion: boolean; high_contrast: boolean; text_size: "normal" | "large" | "larger" };
  behavior: { confirm_destructive: boolean };
  performance: { ram_cache_cap_mb: number };
  connection: { route_mode: RouteMode };
  appearance: { theme: "dark" | "light" };
}

// The RAM-cache slider/number bounds from the `ram_limits` command (Task 1).
export interface RamLimits { default_mb: number; min_mb: number; max_mb: number }

// Live process + budget memory figures from the `memory_stats` command.
// `used_bytes` is null when the OS process-RSS query is unavailable (fail-soft).
export interface MemoryStats { used_bytes: number | null; budget_bytes: number }

// --- T6 (Shamir K-of-N recovery-key custody ceremony) DTO mirrors ---
// `split_recovery_key`'s response: `n` wire-encoded MSHARE1 share strings (the
// interchange unit, spec §5/§8 — deliberately allowed to cross the seam) plus
// the non-secret label/k/n. The frontend holds `shares` only transiently for
// the one-at-a-time reveal wizard and drops the reference once every share has
// been shown (spec §4.4/§11).
export interface SplitRecoveryKeyResponse {
  shares: string[];
  label: string;
  k: number;
  n: number;
}

// `add_recovery_share`'s response: count only (`have`/`need`) + the ceremony's
// label — the share text itself never appears here (spec §6 step 1: a share,
// once accepted, is never redisplayed).
export interface AddShareResponse {
  have: number;
  need: number;
  label: string;
}

// `reconstruct_recovery_key`'s response: an opaque handle into the backend's
// CeremonySession + the non-secret label. The reconstructed key itself NEVER
// crosses the seam — this is not yet a "success"; see ProveResponse below
// (spec §6 step 4, the load-bearing prove gate).
export interface ReconstructResponse {
  ceremony_handle: string;
  label: string;
}

// `prove_reconstructed_key`'s response. `verified: false` is a SUCCESSFUL
// proof outcome (the reconstruction was wrong / from a different key set) —
// it is never surfaced as an error; only `verified: true` unlocks the green
// success state.
export interface ProveResponse {
  verified: boolean;
}
