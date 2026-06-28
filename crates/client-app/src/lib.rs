//! MaxSecu media client app library: the Tauri command catalog and the
//! connection/auth orchestration over the client-core TCB. The thin binary
//! (`main.rs`) wires these into a Tauri app; integration tests drive the same
//! modules directly.
pub mod error;
pub mod dto;
pub mod config;
pub mod keystore;
pub mod state;
pub mod transport;
pub mod session;
pub mod commands;
