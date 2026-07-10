//! MaxSecu portable server launcher (spec §8.2). Lays out a portable folder,
//! generates a DEV self-signed pinned cert + DEV D5 key, and serves the
//! secret-free server over TLS. The DEV profile runs with no external deps
//! (MemoryStore + FsBlobStore); PROD parity (Postgres + injected cert/sink) is
//! behind a config flag. The DEV D5 seed is SECURITY-DEGRADED — never a
//! production ceremony key. Enrollment is registration-key only (no bootstrap
//! secret); the recovery account + first key are provisioned by `maxsecu-setup`.
#![forbid(unsafe_code)]

use maxsecu_portable_server::{config::LauncherConfig, run};

fn main() -> std::io::Result<()> {
    // `print-fingerprint` subcommand (design 2026-07-10 §3): deterministically
    // emit the connection-code fingerprint of the exported pins to STDOUT and
    // exit, so `install-server.sh` can read it directly instead of scraping logs.
    // Runs BEFORE the tokio runtime / normal serve path.
    if std::env::args().nth(1).as_deref() == Some("print-fingerprint") {
        return print_fingerprint();
    }

    let cfg = LauncherConfig::from_env();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run::run(cfg))
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
