export interface ConnState { state: string }
export interface AuthStateMsg { state: string }
export interface GlassbreakResponse { username: string; password: string; user_id: string }
export interface MintedKeyResponse { registration_key: string }
export interface AccountStateMsg { state: "unknown" | "pending" | "active" }

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
