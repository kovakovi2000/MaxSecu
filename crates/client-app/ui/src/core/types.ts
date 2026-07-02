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
}

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
export interface Settings {
  a11y: { reduced_motion: boolean; high_contrast: boolean; text_size: "normal" | "large" | "larger" };
  behavior: { confirm_destructive: boolean };
  performance: { ram_cache_cap_mb: number };
  connection: { use_tor: boolean };
  appearance: { theme: "dark" | "light" };
}

// The RAM-cache slider/number bounds from the `ram_limits` command (Task 1).
export interface RamLimits { default_mb: number; min_mb: number; max_mb: number }

// Live process + budget memory figures from the `memory_stats` command.
// `used_bytes` is null when the OS process-RSS query is unavailable (fail-soft).
export interface MemoryStats { used_bytes: number | null; budget_bytes: number }

// --- Video player: one-shot duration metadata emitted at open (maxsecu://video-info) ---
export interface VideoInfo { duration_ms: number; fragment_count: number }
