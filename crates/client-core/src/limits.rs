//! Shared client-side framing/size limits (parameters §1.2/§4, DESIGN §12.10/D23).
//!
//! These are the bound-check values both the upload core (when it frames a
//! stream) and the download core (when it accepts server-supplied framing
//! fields, before allocating) enforce. A single source of truth so the two
//! sides cannot drift.

/// Minimum accepted chunk size (4 KiB).
pub const CHUNK_SIZE_MIN: u32 = 4 * 1024;

/// Maximum accepted chunk size (8 MiB).
pub const CHUNK_SIZE_MAX: u32 = 8 * 1024 * 1024;

/// Anti-DoS cap on the *framing fields* only (not a product size limit, D31):
/// reject when `chunk_count · chunk_size` exceeds 256 GiB.
pub const MAX_ADDRESSABLE_BYTES: u64 = 256 * 1024 * 1024 * 1024;

/// Absolute first-contact `version` ceiling (parameters §4 / D23) — a sanity cap
/// applied when the client has no trust-on-last-use record for the file yet.
pub const FIRST_CONTACT_VERSION_CEILING: u64 = 1_000_000;

/// Maximum accepted re-share ancestor-grant chain depth (§12.3a/§12.5). Each
/// rotation re-roots every carried recipient under the new author, so a real
/// chain is only the re-shares since the last rotation — typically 1–3. This is
/// a hard fail-closed anti-DoS bound on a server-supplied chain; a cycle guard
/// rejects repeated granters independently. Pinned in parameters.md §1.2.
pub const MAX_GRANT_CHAIN_DEPTH: usize = 32;
