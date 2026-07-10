//! MaxSecu portable server launcher (spec §8.2). Lays out a portable folder,
//! generates a DEV self-signed pinned cert + DEV D5 key, and serves the
//! secret-free server over TLS. The DEV profile runs with no external deps
//! (MemoryStore + FsBlobStore); PROD parity (Postgres + injected cert/sink) is
//! behind a config flag. The DEV D5 seed is SECURITY-DEGRADED — never a
//! production ceremony key. Enrollment is registration-key only (no bootstrap
//! secret); the recovery account + first key are provisioned by `maxsecu-setup`.
#![forbid(unsafe_code)]

use maxsecu_portable_server::{config::LauncherConfig, layout::Layout, run};

fn main() -> std::io::Result<()> {
    // `print-fingerprint` subcommand (design 2026-07-10 §3): deterministically
    // emit the connection-code fingerprint of the exported pins to STDOUT and
    // exit, so `install-server.sh` can read it directly instead of scraping logs.
    // Runs BEFORE the tokio runtime / normal serve path.
    match std::env::args().nth(1).as_deref() {
        Some("print-fingerprint") => return print_fingerprint(),
        // Offline-D5 ceremony (spec §6/§8): the CERT-ONLY fingerprint. While
        // awaiting delegation the directory_pub does not exist server-side, so the
        // ceremony pins the cert with `pin_fingerprint(cert, &[])`.
        Some("print-cert-fingerprint") => return print_cert_fingerprint(),
        // The one-time bootstrap delegation token (from `config/`), for
        // `install-server.sh` to hand to `install-client`.
        Some("print-token") => return print_token(),
        _ => {}
    }

    let cfg = LauncherConfig::from_env();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run::run(cfg))
}

/// Read `<data_dir>/client-pins/server_cert.der` and print the CERT-ONLY
/// `pin_fingerprint(cert, &[])` — the fingerprint the offline-D5 ceremony uses to
/// pin TLS before any directory_pub exists (spec §6). Exits non-zero on a
/// missing/unreadable cert.
fn print_cert_fingerprint() -> std::io::Result<()> {
    let data_dir = LauncherConfig::from_env().data_dir;
    let cert_path = data_dir.join("client-pins").join("server_cert.der");
    let cert = match std::fs::read(&cert_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "print-cert-fingerprint: cannot read {}: {e}",
                cert_path.display()
            );
            std::process::exit(1);
        }
    };
    println!("{}", maxsecu_crypto::pin_fingerprint(&cert, &[]));
    Ok(())
}

/// Print the one-time bootstrap delegation token
/// (`<data_dir>/config/bootstrap_delegation_token.txt`) to STDOUT. Exits non-zero
/// if absent (already delegated / not a Prod install).
fn print_token() -> std::io::Result<()> {
    let layout = Layout::ensure(&LauncherConfig::from_env().data_dir)?;
    let path = layout.bootstrap_token_path();
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            println!("{}", s.trim());
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "print-token: no one-time token at {} ({e}) — already delegated?",
                path.display()
            );
            std::process::exit(1);
        }
    }
}

/// Read `<data_dir>/client-pins/{server_cert.der,directory_pub.der}` (data dir
/// resolved the same way the server resolves it, from `MAXSECU_DATA_DIR`), print
/// `maxsecu_crypto::pin_fingerprint` to STDOUT, and exit 0. A missing/unreadable
/// pin file prints a clear STDERR message and exits non-zero (no partial output).
fn print_fingerprint() -> std::io::Result<()> {
    let data_dir = LauncherConfig::from_env().data_dir;
    let pins = data_dir.join("client-pins");
    let cert_path = pins.join("server_cert.der");
    let dir_path = pins.join("directory_pub.der");

    let cert = match std::fs::read(&cert_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "print-fingerprint: cannot read pin file {}: {e}",
                cert_path.display()
            );
            std::process::exit(1);
        }
    };
    let dir = match std::fs::read(&dir_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "print-fingerprint: cannot read pin file {}: {e}",
                dir_path.display()
            );
            std::process::exit(1);
        }
    };

    println!("{}", maxsecu_crypto::pin_fingerprint(&cert, &dir));
    Ok(())
}
