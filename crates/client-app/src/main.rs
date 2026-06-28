#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod error;
mod dto;
mod config;
mod keystore;
mod state;
mod transport;
mod session;
mod commands;

use commands::auth::{AppDir, Session};

fn main() {
    // Portable layout: keystore/config/pinned-cert live beside the exe so the
    // folder travels (stack.md §5.2). Fall back to "." if the path is unknown.
    let app_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    tauri::Builder::default()
        .manage(AppDir(app_dir))
        .manage(Session::new())
        .invoke_handler(tauri::generate_handler![
            commands::connection::connect,
            commands::auth::unlock_keystore,
            commands::auth::logout,
            commands::stubs::list_feed,
            commands::stubs::register_glassbreak,
        ])
        .run(tauri::generate_context!())
        .expect("error while running MaxSecu client");
}
