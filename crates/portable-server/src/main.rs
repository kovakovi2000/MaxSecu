//! MaxSecu portable server launcher (spec §8.2). Lays out a portable folder,
//! generates a DEV self-signed pinned cert + DEV D5 key, and serves the
//! secret-free server over TLS. The DEV profile runs with no external deps
//! (MemoryStore + FsBlobStore); PROD parity (Postgres + injected cert/sink) is
//! behind a config flag. The DEV D5 seed is SECURITY-DEGRADED — never a
//! production ceremony key. Enrollment is registration-key only (no bootstrap
//! secret); the recovery account + first key are provisioned by `maxsecu-setup`.
#![forbid(unsafe_code)]

mod backup_cli;

use maxsecu_portable_server::{config::LauncherConfig, layout::Layout, run};

/// Printed for `help` / `--help` / `-h`, and on stderr for an unknown subcommand.
/// Running with NO arguments is what starts the server (that is how the systemd
/// unit invokes it); every configuration knob is an environment variable, so there
/// are deliberately no serve-time flags to document here.
const USAGE: &str = "\
maxsecu-portable-server -- MaxSecu server launcher

USAGE:
    maxsecu-portable-server                  start the server (how the systemd unit runs it)
    maxsecu-portable-server <SUBCOMMAND>

SUBCOMMANDS:
    print-fingerprint         print the connection-code fingerprint of the exported pins
    print-cert-fingerprint    print the CERT-ONLY fingerprint (used by the offline-D5 ceremony)
    print-token               print the one-time bootstrap delegation token
    backup [--keep N]         seal a passphrase-encrypted backup onto the cold tier
    restore --from <stamp>    restore from a sealed bundle
    list-backups              list the bundles on the cold tier
    restore-db-merge [--apply]  merge a restored dump into the live database
    verify-restored-blobs     re-run the blob-resolution audit
    help, --help, -h          show this message

CONFIGURATION is by environment variable (MAXSECU_DATA_DIR, MAXSECU_PORT,
DATABASE_URL, ...). MAXSECU_DATA_DIR is resolved RELATIVE TO THE CURRENT DIRECTORY
when unset -- run this from the wrong directory without it and the server will mint
a brand-new TLS cert and directory trust root, which locks out every pinned client.";

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
        // Server backup & rollback (design 2026-07-16). Like the print-*
        // subcommands these run BEFORE the serve path's runtime — each builds its
        // own. `backup_cli` documents the exact CLI and the binary-vs-driver split
        // the shell drivers (phase 3 stage 2) implement against.
        Some("backup")
        | Some("restore")
        | Some("list-backups")
        | Some("restore-db-merge")
        | Some("verify-restored-blobs") => {
            return backup_cli::run(&std::env::args().collect::<Vec<_>>());
        }
        Some("help") | Some("--help") | Some("-h") => {
            println!("{USAGE}");
            return Ok(());
        }
        // NO ARGUMENT AT ALL is the ONLY path that starts a server. That is exactly
        // how the systemd unit runs it (install-server.sh writes a bare
        // `ExecStart=<binary>` with no arguments), and every other entry point above
        // returns before the serve path.
        None => {}
        // An UNRECOGNIZED argument is a hard error. It used to fall through to `{}`
        // and start a server, which is a genuine footgun with two teeth:
        //
        //   * `maxsecu-portable-server backup ...` on a binary that predates the
        //     backup subcommand does not fail — it boots a SECOND server, as root,
        //     against the same database and data dir, holding the passphrase on
        //     stdin, with no timeout. That is precisely what the first upgrade into
        //     the backup feature does if `--no-backup` is forgotten, and on a box
        //     whose server is not on the default port there is nothing to collide
        //     with, so it serves forever and the upgrade hangs.
        //   * Any mistyped subcommand (`--help` included) run from the source
        //     directory with MAXSECU_DATA_DIR unset resolves the data dir RELATIVE
        //     to the cwd, finds no cert there, and silently MINTS A NEW TLS CERT AND
        //     A NEW DIRECTORY TRUST ROOT. On a real VPS that is a new server
        //     identity: every pinned client would fail the handshake.
        //
        // Refusing is safe for existing deployments: the unit passes no arguments,
        // and every caller in-tree (scripts/backup-server.sh, scripts/restore-server.sh,
        // scripts/upgrade-server.sh) uses one of the subcommands matched above.
        Some(other) => {
            eprintln!("error: unknown subcommand: {other}");
            eprintln!("       (refusing to start a server for an argument I do not recognize --");
            eprintln!(
                "        that would risk minting a NEW trust root or running a SECOND server)"
            );
            eprintln!();
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
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
