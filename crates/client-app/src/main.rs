// Hide the Windows console window for ALL profiles (a debug build would otherwise
// pop a cmd window behind the GUI). Was gated on `not(debug_assertions)`.
#![windows_subsystem = "windows"]

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

    // Initial cache cap from persisted settings, clamped to the live RAM bounds.
    // `load` normalizes a present file, but the missing-file default (1 GiB)
    // is not; `normalized()` here also bounds that first-run default to the
    // (total − 6 GB) ceiling so a small-RAM machine can't start over-cap. MiB → bytes.
    let cap_bytes = SettingsConfig::load(&app_dir)
        .normalized()
        .performance
        .ram_cache_cap_mb as usize
        * 1024
        * 1024;

    // Initialize the process-wide Tor state (arti state under <app-dir>/config/tor).
    // Lazily bootstrapped on the first TorOnly connect; read only by the connection
    // helpers on the TorOnly path.
    maxsecu_client_app::tor::init(app_dir.join("config"));

    let app = tauri::Builder::default()
        .manage(AppDir(app_dir))
        .manage(Session::new())
        .manage(ConnectLock::new())
        .manage(maxsecu_client_app::commands::recovery_login::RecoveryLogin::new())
        .manage(maxsecu_client_app::jobs::UploadJobs::new())
        .manage(maxsecu_client_app::jobs::BundleJobs::new())
        .manage(maxsecu_client_app::jobs::VideoJobs::new())
        .manage(maxsecu_client_app::jobs::VideoPrepareCancel::default())
        .manage(ContentCache::new(cap_bytes))
        .invoke_handler(tauri::generate_handler![
            maxsecu_client_app::commands::connection::connect,
            maxsecu_client_app::commands::auth::unlock_keystore,
            maxsecu_client_app::commands::auth::logout,
            maxsecu_client_app::commands::feed::list_feed,
            maxsecu_client_app::commands::feed::decrypt_card,
            maxsecu_client_app::commands::viewer::open_content,
            maxsecu_client_app::commands::bundle::open_bundle,
            maxsecu_client_app::commands::search::search_local,
            maxsecu_client_app::commands::dialog::pick_file,
            maxsecu_client_app::commands::register::register_with_key,
            maxsecu_client_app::commands::startup::startup_mode,
            maxsecu_client_app::commands::admin::mint_registration_key,
            maxsecu_client_app::commands::recovery_login::request_recovery_challenge,
            maxsecu_client_app::commands::recovery_login::answer_recovery_challenge,
            maxsecu_client_app::commands::upload::stage_upload,
            maxsecu_client_app::commands::upload::stage_bundle,
            maxsecu_client_app::commands::upload::confirm_upload,
            maxsecu_client_app::commands::upload::confirm_bundle,
            maxsecu_client_app::commands::upload::cancel_upload,
            maxsecu_client_app::commands::upload::cancel_bundle,
            maxsecu_client_app::commands::upload::cancel_video_prepare,
            maxsecu_client_app::commands::upload::upload_jobs,
            maxsecu_client_app::commands::upload::resume_upload,
            maxsecu_client_app::commands::upload::list_pending_uploads,
            maxsecu_client_app::commands::upload::dismiss_pending_upload,
            maxsecu_client_app::commands::share::reshare_file,
            maxsecu_client_app::commands::share::resolve_recipient,
            maxsecu_client_app::commands::share::list_file_recipients,
            maxsecu_client_app::commands::share::list_contacts,
            maxsecu_client_app::commands::settings::get_settings,
            maxsecu_client_app::commands::settings::set_settings,
            maxsecu_client_app::commands::settings::change_password,
            maxsecu_client_app::commands::settings::export_keystore,
            maxsecu_client_app::ram::ram_limits,
            maxsecu_client_app::ram::memory_stats,
            maxsecu_client_app::commands::video::open_video,
            maxsecu_client_app::commands::video::cancel_video,
        ])
        .register_asynchronous_uri_scheme_protocol("stream", |ctx, request, responder| {
            let app = ctx.app_handle().clone();
            // Parse "…/media/<file_id_hex>" and the Range header up front (cheap, sync).
            let path = request.uri().path().to_string();
            let range_header = request
                .headers()
                .get(http::header::RANGE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            tauri::async_runtime::spawn(async move {
                let resp = maxsecu_client_app::commands::video::stream_media(
                    &app,
                    &path,
                    range_header.as_deref(),
                )
                .await;
                responder.respond(resp);
            });
        })
        .build(tauri::generate_context!())
        .expect("error while running MaxSecu client");

    // Shutdown handling:
    // * `ExitRequested` (fired first, before teardown): flip the in-flight video
    //   `stage_upload` transcode's cancel token so its confined ffmpeg / re-mux child
    //   is terminated (via the watchdog's cancel poll) before the process exits — no
    //   orphaned confined child, prompt shutdown. Best-effort (no-op if none running).
    // * `Exit` (unchanged): zeroize the decrypted-content cache so no plaintext
    //   survives the process (spec §6 — zeroized on app close, in addition to on-evict).
    app.run(|app_handle, event| match event {
        tauri::RunEvent::ExitRequested { .. } => {
            if let Some(prepare_cancel) =
                app_handle.try_state::<maxsecu_client_app::jobs::VideoPrepareCancel>()
            {
                if let Some(flag) = prepare_cancel.0.lock().unwrap().as_ref() {
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        tauri::RunEvent::Exit => {
            if let Some(cache) = app_handle.try_state::<ContentCache>() {
                cache.clear_and_zeroize();
            }
        }
        _ => {}
    });
}
