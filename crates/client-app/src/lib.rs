//! MaxSecu media client app library: the Tauri command catalog and the
//! connection/auth orchestration over the client-core TCB. The thin binary
//! (`main.rs`) wires these into a Tauri app; integration tests drive the same
//! modules directly.
pub mod admin;
pub mod bootstrap;
pub mod commands;
pub mod config;
pub mod content_cache;
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
pub mod session;
pub mod state;
pub mod tor;
pub mod transport;
pub mod upload;
pub mod upload_staging;
pub mod stream;
pub mod video;
