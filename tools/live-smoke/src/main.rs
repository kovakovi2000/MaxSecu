//! Headless functional oracle for the full-install E2E harness. Drives the REAL
//! client-core/client-app code paths against a LIVE installed MaxSecu server over
//! the pinned TLS transport. Any failed assertion returns Err → process exit 1.
//!
//! Usage:
//!   maxsecu-live-smoke --server <ip:port> --host <ip> --client-dir <dist/MaxSecuClient>
//!                      [--phase seed|verify|all] [--state <path>]
//!
//! --server      dial target ip:port (the WSL server's --public address)
//! --host        the cert-SAN name to verify against == the public IP (same as --server host)
//! --client-dir  the built admin client dir: reads config/server_cert.der,
//!               config/directory_pub.der, and register.key (the admin's first key)
//! --phase       which half of the backup/rollback E2E to run (default `all`):
//!                 all    — TODAY's full functional smoke (steps::run), the only
//!                          mode test-full-install.ps1 uses. `--state` is rejected.
//!                 seed   — enroll + upload (a blog AND an image, so a PINNED
//!                          Thumbnail/Preview stream round-trips) into an app-dir
//!                          beside the state file, then record `--state`.
//!                 verify — reopen the SAME sealed app-dir (no re-enroll), assert
//!                          identity + directory binding + every recorded file's
//!                          content survived the restore, then prove the WRITE path.
//! --state       state-file path; REQUIRED for seed|verify, REJECTED for all.

mod net;
mod steps;

use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    All,
    Seed,
    Verify,
}

struct Args {
    server: String,
    host: String,
    client_dir: PathBuf,
    phase: Phase,
    state: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut server = None;
    let mut host = None;
    let mut client_dir = None;
    let mut phase = Phase::All;
    let mut state = None;
    let mut it = std::env::args().skip(1);
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
                    Some(other) => {
                        return Err(format!("unknown --phase '{other}' (want seed|verify|all)"))
                    }
                    None => return Err("missing value for --phase".into()),
                };
            }
            "--state" => state = it.next(),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let args = Args {
        server: server.ok_or("missing --server")?,
        host: host.ok_or("missing --host")?,
        client_dir: client_dir.ok_or("missing --client-dir")?.into(),
        phase,
        state: state.map(Into::into),
    };
    // `--state` is required for the split phases (they read/write it) and rejected
    // for `all` (which is the untouched full smoke and has no state file).
    match args.phase {
        Phase::All => {
            if args.state.is_some() {
                return Err("--state is not valid with --phase all".into());
            }
        }
        Phase::Seed | Phase::Verify => {
            if args.state.is_none() {
                return Err("--state <path> is required for --phase seed|verify".into());
            }
        }
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
