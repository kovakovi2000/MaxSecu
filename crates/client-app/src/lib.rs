//! MaxSecu media client app library: the Tauri command catalog and the
//! connection/auth orchestration over the client-core TCB. The thin binary
//! (`main.rs`) wires these into a Tauri app; integration tests drive the same
//! modules directly.
pub mod commands;
pub mod config;
pub mod dto;
pub mod error;
pub mod keystore;
pub mod session;
pub mod state;
pub mod transport;
