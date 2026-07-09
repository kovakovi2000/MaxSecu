// Hide the Windows console window for ALL profiles (a debug build would otherwise
// pop a cmd window behind the GUI). Was gated on `not(debug_assertions)`.
#![windows_subsystem = "windows"]

use maxsecu_client_app::commands::auth::{AppDir, ConnectLock, Session};
use maxsecu_client_app::config::SettingsConfig;
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

    // Redirect the process temp dir INTO the portable folder BEFORE anything resolves
    // a temp path — critically before the WebView2 child spawns, since it inherits our
    // environment. This keeps WebView2's browser scratch (msedge_*, WebView2Downloads)
    // AND our own transient scratch (the confined video-transcode per-job dirs) inside
    // <app_dir>/tmp, which the exit-wipe removes.
    //
    // The temp dir is a SIBLING of `webview/`, NOT nested inside it: WebView2
    // ACL-locks its own user-data directory (`webview/`), and a confined-ffmpeg job
    // dir created under that locked tree fails the AppContainer child's access
    // ("That video could not be processed."). A plain `<app_dir>/tmp` has ordinary
    // inherited ACLs — identical to the OS-temp location the confinement was proven
    // against — so the per-job `grant_path_to_appcontainer` ACE + bypass-traverse work
    // exactly as before and GPU-accelerated transcode is preserved.
    //
    // Env is read lazily by `std::env::temp_dir()`, so setting it now takes effect for
    // every later call. Best-effort: a create failure leaves the OS default in place
    // rather than crashing startup.
    let webview_dir = app_dir.join("webview");
    let app_tmp = app_dir.join("tmp");
    if std::fs::create_dir_all(&app_tmp).is_ok() {
        std::env::set_var("TEMP", &app_tmp);
        std::env::set_var("TMP", &app_tmp);
        // Give the temp root an inheritable CREATOR OWNER Full-Control ACE so each
        // confined-transcode job dir created beneath it grants its creator
        // WRITE_OWNER — required for the AppContainer grant to drop that dir to a Low
        // integrity label. Without this, on a data-drive volume whose inherited ACL is
        // only "Modify", the label set is ACCESS_DENIED and video ingest fails ("That
        // video could not be processed."). Reproduces the ACL %TEMP% already carries.
        // Best-effort: a failure leaves confinement intact, only the on-drive transcode
        // may still hit the limitation. Windows-only (the confinement/label machinery is).
        #[cfg(windows)]
        let _ = maxsecu_media_launcher::grant_creator_owner_full_control(&app_tmp);
    }

    // Initial cache cap from persisted settings, clamped to the live RAM bounds.
    // `load` normalizes a present file, but the missing-file default (1 GiB)
    // is not; `normalized()` here also bounds that first-run default to the
    // (total − 6 GB) ceiling so a small-RAM machine can't start over-cap. MiB → bytes.
    let normalized = SettingsConfig::load(&app_dir).normalized();
    let media_cap_mb = normalized.performance.media_cache_cap_mb;
    let thumb_cap_mb = normalized.performance.thumb_cache_cap_mb;
    let location = normalized.performance.cache_location;
    // Live-channel cap for the authed connection pool = the persisted feed
    // concurrency (already clamped to 1..=8 by `normalized`). Feed-card decodes
    // borrow up to this many concurrent authed channels; the UI never drives more
    // than `feed_concurrency` at once. Read ONCE at startup — changing
    // `feed_concurrency` in settings takes effect on the next app restart.
    let pool_cap = normalized.performance.feed_concurrency as usize;

    // WebView2 user-data folder lives INSIDE the portable folder (`webview_dir`,
    // defined above) so localStorage, cache, cookies, and GPU cache never escape
    // <app_dir>. Wiped on exit.
    // The persisted skin, injected pre-paint via an initialization script so boot.js
    // can apply it before first paint with no flash (settings.json is the source of truth).
    let boot_frontend = normalized.appearance.frontend.clone();

    // Initialize the process-wide Tor state (arti state under <app-dir>/config/tor).
    // Lazily bootstrapped on the first TorOnly connect; read only by the connection
    // helpers on the TorOnly path.
    maxsecu_client_app::tor::init(app_dir.join("config"));

    // Process-global ephemeral seal shared by both ciphertext-in-RAM caches: the
    // Media cache's `Content` payloads and the Thumbnails cache's `Card` meta are
    // sealed under it, so any OS page-out spills only ciphertext. Both caches are
    // opened ONCE at startup; `open`/`new` return an `io::Result`, and a Disk-mode
    // open failure (bad/unwritable dir) aborts startup here via `expect` (an
    // honest fail-fast panic) rather than limping on with a broken cache.
    let seal = std::sync::Arc::new(maxsecu_client_app::session_seal::SessionSeal::generate());
    let media_cache =
        maxsecu_client_app::media_cache::MediaCache::open(&app_dir, media_cap_mb, location)
            .expect("open media cache");
    let thumb_cache = maxsecu_client_app::thumb_cache::ThumbCache::new(
        &app_dir,
        thumb_cap_mb,
        location,
        seal.clone(),
    )
    .expect("open thumb cache");

    // Stash the Disk-mode gauge denominator: probe the free space on the volume
    // holding `app_dir` ONCE now (while `app_dir` is still un-moved). `cache_stats`
    // hands this back as the denominator in Disk mode; `None` → the UI shows the
    // raw on-disk size without a denominator.
    let disk_free_est = maxsecu_client_app::disk_free::free_bytes_for(&app_dir);

    let app = tauri::Builder::default()
        .manage(AppDir(app_dir))
        .manage(Session::new())
        .manage(ConnectLock::new())
        .manage(maxsecu_client_app::commands::recovery_login::RecoveryLogin::new())
        .manage(maxsecu_client_app::jobs::UploadJobs::new())
        .manage(maxsecu_client_app::jobs::BundleJobs::new())
        .manage(maxsecu_client_app::jobs::VideoJobs::new())
        .manage(maxsecu_client_app::jobs::VideoPrepareCancel::default())
        .manage(maxsecu_client_app::state::H264EncoderCache::default())
        .manage(seal.clone())
        .manage(media_cache)
        .manage(thumb_cache)
        .manage(maxsecu_client_app::disk_free::DiskFreeEstimate(disk_free_est))
        .manage(maxsecu_client_app::directory::DirectoryCache::new())
        .manage(maxsecu_client_app::commands::pool::AppPool::new(pool_cap))
        .setup(move |app| {
            use tauri::{WebviewUrl, WebviewWindowBuilder};
            // Set the injected global BEFORE any page script (incl. boot.js) runs.
            let boot_script = format!(
                "window.__MAXSECU_BOOT__ = {{ frontend: {} }};",
                serde_json::to_string(&boot_frontend).unwrap_or_else(|_| "\"default\"".into())
            );
            // WebView2/Chromium command-line args. Setting this REPLACES wry's
            // defaults, so we re-list them first, then add our hardening:
            //   * wry defaults (must keep): msWebOOUI/msPdfOOUI (out-of-proc UI off),
            //     msSmartScreenProtection (no SmartScreen phone-home),
            //     --autoplay-policy=no-user-gesture-required (autoplay defaults on in
            //     wry, our media player relies on it).
            //   * --disable-gpu-shader-disk-cache: stop the GPU driver writing its
            //     shader cache OUTSIDE the folder, WITHOUT disabling GPU-accelerated
            //     video decode (we do NOT pass --disable-gpu).
            //   * msImplicitSignin + msSingleSignOnOSForPrimaryAccountIsShared:
            //     best-effort suppression of Edge's implicit OS single-sign-on, the
            //     path that makes the runtime's identity broker (oneauth.dll) read the
            //     machine's Microsoft/OneDrive account store. We have no MS-account
            //     integration, so disabling it changes nothing we use.
            //   * --disable-spell-checking: WebView2 spellchecks typed text (post
            //     title/caption) via the Windows spellchecker, which LEARNS words into
            //     the user's OS personal dictionary (%APPDATA%\Microsoft\Spelling\*) —
            //     a trace outside the folder. We don't need spellcheck in a media
            //     client, so turn it off entirely.
            const BROWSER_ARGS: &str = concat!(
                "--disable-features=",
                "msWebOOUI,msPdfOOUI,msSmartScreenProtection,",
                "msImplicitSignin,msSingleSignOnOSForPrimaryAccountIsShared",
                " --disable-gpu-shader-disk-cache",
                " --disable-spell-checking",
                " --autoplay-policy=no-user-gesture-required",
            );
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("MaxSecu")
                .inner_size(1100.0, 720.0)
                .resizable(true)
                .maximized(true)
                .data_directory(webview_dir.clone())
                .additional_browser_args(BROWSER_ARGS)
                .initialization_script(boot_script)
                .build()?;
            Ok(())
        })
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
            maxsecu_client_app::commands::dialog::pick_files,
            maxsecu_client_app::commands::dialog::save_file,
            maxsecu_client_app::commands::dialog::pick_folder,
            maxsecu_client_app::commands::download_cmd::download_content,
            maxsecu_client_app::commands::delete_cmd::delete_content,
            maxsecu_client_app::commands::register::register_with_key,
            maxsecu_client_app::commands::startup::startup_mode,
            maxsecu_client_app::commands::admin::mint_registration_key,
            maxsecu_client_app::commands::recovery_login::request_recovery_challenge,
            maxsecu_client_app::commands::recovery_login::answer_recovery_challenge,
            maxsecu_client_app::commands::upload::stage_upload,
            maxsecu_client_app::commands::upload::stage_bundle,
            maxsecu_client_app::commands::upload::confirm_upload,
            maxsecu_client_app::commands::upload::confirm_bundle,
            maxsecu_client_app::commands::upload::retry_confirm,
            maxsecu_client_app::commands::upload::cancel_upload,
            maxsecu_client_app::commands::upload::cancel_bundle,
            maxsecu_client_app::commands::upload::cancel_video_prepare,
            maxsecu_client_app::commands::upload::upload_jobs,
            maxsecu_client_app::commands::upload::resume_upload,
            maxsecu_client_app::commands::upload::list_pending_uploads,
            maxsecu_client_app::commands::upload::dismiss_pending_upload,
            maxsecu_client_app::commands::share::reshare_file,
            maxsecu_client_app::commands::share::reshare_bundle,
            maxsecu_client_app::commands::share::resolve_recipient,
            maxsecu_client_app::commands::share::list_file_recipients,
            maxsecu_client_app::commands::share::list_contacts,
            maxsecu_client_app::commands::settings::system_cores,
            maxsecu_client_app::commands::settings::get_settings,
            maxsecu_client_app::commands::settings::set_settings,
            maxsecu_client_app::commands::settings::change_password,
            maxsecu_client_app::commands::settings::export_keystore,
            maxsecu_client_app::ram::ram_limits,
            maxsecu_client_app::ram::memory_stats,
            maxsecu_client_app::commands::video::open_video,
            maxsecu_client_app::commands::video::cancel_video,
            maxsecu_client_app::commands::video::cache_stats,
            maxsecu_client_app::commands::video::clear_media_cache,
            maxsecu_client_app::commands::video::clear_thumb_cache,
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
    // * `Exit` (D6/D5a): explicitly wipe both app-global caches + the seal key while
    //   the managed state is still alive (a managed-state drop is NOT guaranteed on
    //   shutdown). In Memory mode this zeroizes the in-RAM ciphertext; in Disk mode it
    //   deletes the `cache/media/*` + `cache/thumb/*` backing files. Zeroizing the
    //   ephemeral `SessionSeal` key's in-RAM copy last means sealed blobs paged out
    //   earlier become undecryptable once the live key is gone — with the accepted
    //   residual that a key copy already written to swap BEFORE this wipe (the key is
    //   not `mlock`'d) is outside our control. The cache wipes use the `try_lock`-based
    //   sync variants so this SYNC callback can never panic on a missing runtime
    //   context nor block shutdown.
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
            if let Some(media) =
                app_handle.try_state::<maxsecu_client_app::media_cache::MediaCache>()
            {
                media.clear_and_zeroize_sync(); // Memory → wipe RAM; Disk → delete cache/media/*
            }
            if let Some(thumb) =
                app_handle.try_state::<maxsecu_client_app::thumb_cache::ThumbCache>()
            {
                thumb.clear_and_zeroize_sync(); // Memory → wipe; Disk → delete cache/thumb/*
            }
            if let Some(seal) = app_handle
                .try_state::<std::sync::Arc<maxsecu_client_app::session_seal::SessionSeal>>()
            {
                seal.zeroize(); // wipe the key's in-RAM copy (swap copy from before this is the accepted residual)
            }
            // Wipe the WebView2 user-data folder AND the in-folder temp dir so no
            // browser artifacts or transient transcode scratch persist between runs.
            // Best-effort — never block or panic shutdown.
            if let Some(dir) = app_handle.try_state::<AppDir>() {
                let _ = std::fs::remove_dir_all(dir.0.join("webview"));
                let _ = std::fs::remove_dir_all(dir.0.join("tmp"));
            }
        }
        _ => {}
    });
}
