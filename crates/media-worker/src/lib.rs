//! Sandboxed media-decode **worker** crate (DESIGN §8.1/D30, media-sandbox).
//!
//! This crate carries the two codec-bearing pieces of the media sandbox — the
//! in-process AV1/CMAF decoder ([`VideoSession`], `mod session`, linking
//! `rav1d`/`symphonia`) and the worker binary (`src/main.rs`) that runs that
//! decode in the confined subprocess. The **codec-free launcher** (the spawn /
//! framing / proto side that a key-holding process drives) lives in the separate
//! [`maxsecu_media_launcher`] crate, so the decoder can never be unified into a
//! trusted consumer by Cargo feature resolution. The launcher items are re-exported
//! here unchanged so the worker bin and the integration tests keep their existing
//! `maxsecu_media_worker::{...}` import paths.

mod session;
pub use session::VideoSession;

// Re-export the codec-free launcher (the spawn / framing / proto side). These
// types live in `maxsecu-media-launcher`; re-homing them keeps the bin's and the
// integration tests' `maxsecu_media_worker::{...}` paths unchanged.
pub use maxsecu_media_launcher::{
    framing, proto, run_decode, ResilientOutcome, SessionError, SubprocessDecoder, TerminalReason,
    VideoSessionDecoder, VideoSubprocessSession, DEFAULT_WORKER_MEMORY_CAP_BYTES,
    MAX_RESPAWNS_PER_WINDOW,
};

#[cfg(windows)]
pub use maxsecu_media_launcher::{
    AppContainerDecoder, AppContainerVideoSession, ConfinedOutput, SpawnError,
};
