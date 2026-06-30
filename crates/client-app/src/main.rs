#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use maxsecu_client_app::commands::auth::{AppDir, ConnectLock, Session};
use maxsecu_client_app::config::SettingsConfig;
use maxsecu_client_app::content_cache::ContentCache;
use tauri::Manager;

fn main() {
    // Portable layout: keystore/config/pinned-cert live beside the exe so the
    // folder travels (stack.md §5.2). Fall back to "." if the path is unknown.
    let app_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // Ensure the portable sub-dirs exist beside the exe (spec §8.1). Best-effort:
    // the individual writers also create their own parents, so a failure here must
    // not crash startup.
    let _ = maxsecu_client_app::layout::ensure_portable_layout(&app_dir);

    // Initial cache cap from persisted settings (normalized to the live RAM
    // bounds at save-time). MiB → bytes.
    let cap_bytes =
        SettingsConfig::load(&app_dir).performance.ram_cache_cap_mb as usize * 1024 * 1024;

    let app = tauri::Builder::default()
        .manage(AppDir(app_dir))
        .manage(Session::new())
        .manage(ConnectLock::new())
        .manage(maxsecu_client_app::jobs::UploadJobs::new())
        .manage(maxsecu_client_app::jobs::VideoJobs::new())
        .manage(ContentCache::new(cap_bytes))
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
            maxsecu_client_app::commands::upload::confirm_upload,
            maxsecu_client_app::commands::upload::cancel_upload,
            maxsecu_client_app::commands::upload::upload_jobs,
            maxsecu_client_app::commands::video::preview_video,
            maxsecu_client_app::commands::settings::get_settings,
            maxsecu_client_app::commands::settings::set_settings,
            maxsecu_client_app::commands::settings::change_password,
            maxsecu_client_app::commands::settings::export_keystore,
            maxsecu_client_app::ram::ram_limits,
            maxsecu_client_app::commands::video::open_video,
            maxsecu_client_app::commands::video::video_seek,
            maxsecu_client_app::commands::video::video_set_volume,
            maxsecu_client_app::commands::video::cancel_video,
        ])
        .build(tauri::generate_context!())
        .expect("error while running MaxSecu client");

    // Zeroize the decrypted-content cache on shutdown so no plaintext survives the
    // process (spec §6 — zeroized on app close, in addition to on-evict).
    app.run(|app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            if let Some(cache) = app_handle.try_state::<ContentCache>() {
                cache.clear_and_zeroize();
            }
        }
    });
}
