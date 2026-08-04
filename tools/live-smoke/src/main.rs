//! Headless functional oracle for the full-install E2E harness. Drives the REAL
//! client-core/client-app code paths against a LIVE installed MaxSecu server over
//! the pinned TLS transport. Any failed assertion returns Err → process exit 1.
//!
//! Usage:
//!   maxsecu-live-smoke --server <ip:port> --host <ip> --client-dir <dist/MaxSecuClient>
//!                      [--phase seed|verify|all|upload-files|download-files] [--state <path>]
//!                      [--out-dir <path>] [--app-dir <path>] [--file <kind>:<path>]...
//!                      [--allow-client-upgrade] [--allow-server-id-change]
//!
//! --server      dial target ip:port (the WSL server's --public address)
//! --host        the cert-SAN name to verify against == the public IP (same as --server host)
//! --client-dir  the built admin client dir: reads config/server_cert.der,
//!               config/directory_pub.der, and register.key (the admin's first key)
//! --phase       which oracle to run (default `all`):
//!                 all            — TODAY's full functional smoke (steps::run), the
//!                                  only mode test-full-install.ps1 uses. `--state`
//!                                  is rejected.
//!                 seed           — enroll + upload (a blog AND an image, so a PINNED
//!                                  Thumbnail/Preview stream round-trips) into an
//!                                  app-dir beside the state file, then record `--state`.
//!                 verify         — reopen the SAME sealed app-dir (no re-enroll),
//!                                  assert identity + directory binding + every
//!                                  recorded file's content survived the restore,
//!                                  then prove the WRITE path.
//!                 upload-files   — PROD-UPGRADE fidelity, PRE half: enroll once (only
//!                                  on a virgin app-dir), upload every `--file` through
//!                                  its real prepare path, read each back, write the
//!                                  recovered plaintext to `--out-dir`, and record every
//!                                  file_id + per-stream digest into `--state`.
//!                 download-files — PROD-UPGRADE fidelity, POST half: reopen the SAME
//!                                  sealed app-dir (NO re-enroll), re-download every
//!                                  recorded file, compare every stream digest against
//!                                  what was recorded, write recovered plaintext to
//!                                  `--out-dir`, then do one fresh post to prove the
//!                                  write path.
//! --state       state-file path; REQUIRED for seed|verify|upload-files|download-files,
//!               REJECTED for all.
//! --out-dir     where recovered plaintext is written; REQUIRED for upload-files and
//!               download-files, REJECTED for every other phase. download-files refuses
//!               an --out-dir equal to the one upload-files used.
//! --app-dir     upload-files only; where the sealed client app-dir lives. Defaults to
//!               `<state>.appdir`. download-files always takes it from `--state`.
//! --file        repeatable, upload-files only: `<kind>:<path>` where kind is
//!               image|generic|blog. `video` is REJECTED — ffmpeg is compiled out of
//!               this oracle (default-features = false) and prepare_video_streams always
//!               re-muxes, so source-byte identity is impossible by design.
//! --allow-client-upgrade    download-files only: permit a DIFFERENT oracle build than
//!                           the one that wrote --state.
//! --allow-server-id-change  download-files only: permit a changed server_id.

mod net;
mod steps;

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
maxsecu-live-smoke --server <ip:port> --host <ip> --client-dir <dist/MaxSecuClient>
                   [--phase all|seed|verify|upload-files|download-files] [--state <path>]
                   [--out-dir <path>] [--app-dir <path>] [--file <kind>:<path>]...
                   [--allow-client-upgrade] [--allow-server-id-change]

phases:
  all             the full functional smoke (default; --state rejected)
  seed            backup/rollback PRE half  — enroll + upload, record --state
  verify          backup/rollback POST half — reopen the sealed app-dir, no re-enroll
  upload-files    prod-upgrade PRE half  — upload every --file, read back, record --state
  download-files  prod-upgrade POST half — re-download everything in --state, no re-enroll

--file kinds: image | generic | blog   ('video' is rejected: ffmpeg is compiled out
                                        of this oracle and video is always re-muxed)";

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    All,
    Seed,
    Verify,
    UploadFiles,
    DownloadFiles,
}

struct Args {
    server: String,
    host: String,
    client_dir: PathBuf,
    phase: Phase,
    state: Option<PathBuf>,
    out_dir: Option<PathBuf>,
    app_dir: Option<PathBuf>,
    files: Vec<String>,
    allow_client_upgrade: bool,
    allow_server_id_change: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut server = None;
    let mut host = None;
    let mut client_dir = None;
    let mut phase = Phase::All;
    let mut state = None;
    let mut out_dir = None;
    let mut app_dir = None;
    let mut files: Vec<String> = Vec::new();
    let mut allow_client_upgrade = false;
    let mut allow_server_id_change = false;
    let mut it = std::env::args().skip(1).peekable();
    if it.peek().is_none() {
        return Err(format!("no arguments given\n\n{USAGE}"));
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "--server" => server = it.next(),
            "--host" => host = it.next(),
            "--client-dir" => client_dir = it.next(),
            "--phase" => {
                phase = match it.next().as_deref() {
                    Some("all") => Phase::All,
                    Some("seed") => Phase::Seed,
                    Some("verify") => Phase::Verify,
                    Some("upload-files") => Phase::UploadFiles,
                    Some("download-files") => Phase::DownloadFiles,
                    Some(other) => {
                        return Err(format!(
                            "unknown --phase '{other}' (want all|seed|verify|upload-files|download-files)\n\n{USAGE}"
                        ))
                    }
                    None => return Err("missing value for --phase".into()),
                };
            }
            "--state" => state = it.next(),
            "--out-dir" => out_dir = it.next(),
            "--app-dir" => app_dir = it.next(),
            "--file" => match it.next() {
                Some(v) => files.push(v),
                None => return Err("missing value for --file".into()),
            },
            "--allow-client-upgrade" => allow_client_upgrade = true,
            "--allow-server-id-change" => allow_server_id_change = true,
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }
    let args = Args {
        server: server.ok_or("missing --server")?,
        host: host.ok_or("missing --host")?,
        client_dir: client_dir.ok_or("missing --client-dir")?.into(),
        phase,
        state: state.map(Into::into),
        out_dir: out_dir.map(Into::into),
        app_dir: app_dir.map(Into::into),
        files,
        allow_client_upgrade,
        allow_server_id_change,
    };
    // `--state` is required for every split phase (they read/write it) and rejected
    // for `all` (the untouched full smoke, which has no state file).
    match args.phase {
        Phase::All => {
            if args.state.is_some() {
                return Err("--state is not valid with --phase all".into());
            }
        }
        Phase::Seed | Phase::Verify | Phase::UploadFiles | Phase::DownloadFiles => {
            if args.state.is_none() {
                return Err(
                    "--state <path> is required for --phase seed|verify|upload-files|download-files"
                        .into(),
                );
            }
        }
    }
    // `--out-dir` belongs to the two file-fidelity phases and only to them.
    match args.phase {
        Phase::UploadFiles | Phase::DownloadFiles => {
            if args.out_dir.is_none() {
                return Err(
                    "--out-dir <path> is required for --phase upload-files|download-files".into(),
                );
            }
        }
        _ => {
            if args.out_dir.is_some() {
                return Err(
                    "--out-dir is only valid with --phase upload-files|download-files".into(),
                );
            }
        }
    }
    if args.phase == Phase::UploadFiles {
        if args.files.is_empty() {
            return Err(
                "at least one --file <kind>:<path> is required for --phase upload-files".into(),
            );
        }
    } else {
        if !args.files.is_empty() {
            return Err("--file is only valid with --phase upload-files".into());
        }
        if args.app_dir.is_some() {
            return Err("--app-dir is only valid with --phase upload-files".into());
        }
    }
    if args.phase != Phase::DownloadFiles
        && (args.allow_client_upgrade || args.allow_server_id_change)
    {
        return Err(
            "--allow-client-upgrade / --allow-server-id-change are only valid with --phase download-files"
                .into(),
        );
    }
    Ok(args)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("live-smoke: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "live-smoke: server={} host={} client_dir={}",
        args.server,
        args.host,
        args.client_dir.display()
    );
    // `all` runs TODAY's steps::run VERBATIM — the mode test-full-install.ps1 drives.
    let result = match args.phase {
        Phase::All => steps::run(&args.server, &args.host, &args.client_dir).await,
        Phase::Seed => {
            let state = args.state.as_deref().expect("seed requires --state");
            steps::seed(&args.server, &args.host, &args.client_dir, state).await
        }
        Phase::Verify => {
            let state = args.state.as_deref().expect("verify requires --state");
            steps::verify(&args.server, &args.host, &args.client_dir, state).await
        }
        Phase::UploadFiles => {
            let state = args
                .state
                .as_deref()
                .expect("upload-files requires --state");
            let out_dir = args
                .out_dir
                .as_deref()
                .expect("upload-files requires --out-dir");
            steps::upload_files(&steps::FilesArgs {
                server: &args.server,
                host: &args.host,
                client_dir: &args.client_dir,
                state,
                app_dir: args.app_dir.as_deref(),
                out_dir,
                files: &args.files,
                allow_client_upgrade: args.allow_client_upgrade,
                allow_server_id_change: args.allow_server_id_change,
            })
            .await
        }
        Phase::DownloadFiles => {
            let state = args
                .state
                .as_deref()
                .expect("download-files requires --state");
            let out_dir = args
                .out_dir
                .as_deref()
                .expect("download-files requires --out-dir");
            steps::download_files(&steps::FilesArgs {
                server: &args.server,
                host: &args.host,
                client_dir: &args.client_dir,
                state,
                app_dir: None,
                out_dir,
                files: &args.files,
                allow_client_upgrade: args.allow_client_upgrade,
                allow_server_id_change: args.allow_server_id_change,
            })
            .await
        }
    };
    match result {
        Ok(()) => {
            println!("LIVE-SMOKE OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("LIVE-SMOKE FAIL: {e}");
            ExitCode::FAILURE
        }
    }
}
