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
pub mod fragment_cache;
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
