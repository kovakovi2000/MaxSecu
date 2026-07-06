//! MaxSecu media client app library: the Tauri command catalog and the
//! connection/auth orchestration over the client-core TCB. The thin binary
//! (`main.rs`) wires these into a Tauri app; integration tests drive the same
//! modules directly.
pub mod commands;
pub mod config;
pub mod content_cache;
pub mod contacts;
pub mod directory;
pub mod direct_link;
pub mod download;
pub mod dto;
pub mod error;
pub mod ffmpeg_bin;
pub mod blob_cache;
/// Back-compat shim (removed in Task 4/5 of the RAM-cache-model rework): the old
/// `fragment_cache` module path still resolves, re-exporting the thin
/// `FragmentCache` wrapper now living in [`blob_cache`]. Lets the existing
/// `commands/video.rs` / `stream.rs` / `jobs.rs` / `video.rs` call sites keep
/// their `crate::fragment_cache::FragmentCache` imports until they migrate.
pub mod fragment_cache {
    pub use crate::blob_cache::FragmentCache;
}
pub mod http_client;
pub mod index;
pub mod jobs;
pub mod keystore;
pub mod layout;
pub mod ram;
pub mod recipients;
pub mod recovery_pin;
pub mod revocations;
pub mod session;
pub mod sink;
pub mod state;
pub mod tofu;
pub mod tor;
pub mod transparency;
pub mod transport;
pub mod upload;
pub mod upload_staging;
pub mod stream;
pub mod video;
