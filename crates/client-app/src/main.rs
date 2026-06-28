#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod error;
mod dto;
mod keystore;
mod config;
mod state;

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running MaxSecu client");
}
