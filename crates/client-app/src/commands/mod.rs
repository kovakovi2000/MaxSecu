//! The Tauri command catalog and managed state. Commands take/return only DTOs
//! (`crate::dto`) + `UiError` and emit serializable state events — no key
//! material, token bytes, or exporter ever crosses this boundary (UI-outside-TCB).

pub mod admin;
pub mod auth;
pub mod bundle;
pub mod connection;
pub mod delete_cmd;
pub mod dialog;
pub mod download_cmd;
pub mod feed;
pub mod pool;
pub mod recovery_login;
pub mod register;
pub mod renew;
pub mod search;
pub mod settings;
pub mod share;
pub mod startup;
pub mod upload;
pub mod video;
pub mod viewer;
