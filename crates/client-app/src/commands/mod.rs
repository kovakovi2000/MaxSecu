//! The Tauri command catalog and managed state. Commands take/return only DTOs
//! (`crate::dto`) + `UiError` and emit serializable state events — no key
//! material, token bytes, or exporter ever crosses this boundary (UI-outside-TCB).

pub mod admin;
pub mod auth;
pub mod bootstrap;
pub mod connection;
pub mod stubs;
