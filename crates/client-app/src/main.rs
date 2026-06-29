#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use maxsecu_client_app::commands::auth::{AppDir, ConnectLock, Session};

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
        .manage(ConnectLock::new())
        .manage(maxsecu_client_app::jobs::UploadJobs::new())
        .invoke_handler(tauri::generate_handler![
            maxsecu_client_app::commands::connection::connect,
            maxsecu_client_app::commands::auth::unlock_keystore,
            maxsecu_client_app::commands::auth::logout,
            maxsecu_client_app::commands::feed::list_feed,
            maxsecu_client_app::commands::feed::decrypt_card,
            maxsecu_client_app::commands::viewer::open_content,
            maxsecu_client_app::commands::search::search_local,
            maxsecu_client_app::commands::bootstrap::register_glassbreak,
            maxsecu_client_app::commands::bootstrap::create_first_admin,
            maxsecu_client_app::commands::bootstrap::register_user,
            maxsecu_client_app::commands::bootstrap::account_status,
            maxsecu_client_app::commands::admin::list_pending,
            maxsecu_client_app::commands::admin::issue_voucher,
            maxsecu_client_app::commands::admin::request_approval,
            maxsecu_client_app::commands::upload::stage_upload,
        ])
        .run(tauri::generate_context!())
        .expect("error while running MaxSecu client");
}
