//! `maxsecu-setup` CLI entry point (spec §4). Config via flags OR env (flags win);
//! mirrors `demo-seed`'s env style. Reads the pinned server cert the same way
//! demo-seed does, builds a pinned-TLS [`Transport`], and drives [`maxsecu_setup::run`].
//!
//! Flags / env:
//!   --server / SETUP_SERVER        TCP dial target       (default 127.0.0.1:8443)
//!   --host   / SETUP_HOST          cert SAN / SNI / Host  (default localhost)
//!   --cert   / SETUP_CERT          server_cert.der path
//!   --data-dir / SETUP_DATA_DIR    fallback cert dir (<data-dir>/client-pins/server_cert.der)
//!   --out    / SETUP_OUT           sealed recovery key blob    (required)
//!   --pin-out / SETUP_PIN_OUT      canonical recovery_pin.bin  (required)
//!   --first-key-out / SETUP_FIRST_KEY_OUT   first registration key  (required)
//!   --passphrase / SETUP_RECOVERY_PW        seals the key blob (else prompted on stdin)

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use zeroize::Zeroizing;

use maxsecu_client_app::transport::{pinned_client_config, Transport};
use maxsecu_setup::{run, SetupError, SetupOpts};

/// Typed outcome of [`real_main`], mapped to a process exit code in [`main`] — replaces
/// smuggling a magic sentinel string through the error channel.
enum SetupExit {
    /// The once-only recovery account already exists (409). Distinct exit code 3 so
    /// scripts can tell "already done" from a real fault.
    AlreadyRegistered,
    /// Any other fault (config / cert / network / protocol / io). Exit code 1.
    Failed(String),
}

// `?` on the config-plumbing errors (missing flag &str, formatted String) folds them
// into `Failed` automatically.
impl From<String> for SetupExit {
    fn from(m: String) -> Self {
        SetupExit::Failed(m)
    }
}
impl From<&str> for SetupExit {
    fn from(m: &str) -> Self {
        SetupExit::Failed(m.to_owned())
    }
}

/// Parse `--key value` / `--flag` pairs into a map (flags win over env).
fn parse_flags() -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if let Some(key) = a.strip_prefix("--") {
            // Support `--key=value` and `--key value`.
            if let Some((k, v)) = key.split_once('=') {
                out.insert(k.to_owned(), v.to_owned());
            } else if let Some(v) = args.next() {
                out.insert(key.to_owned(), v);
            } else {
                out.insert(key.to_owned(), String::new());
            }
        }
    }
    out
}

/// flag → env → default resolution.
fn opt(
    flags: &HashMap<String, String>,
    flag: &str,
    env: &str,
    default: Option<&str>,
) -> Option<String> {
    flags
        .get(flag)
        .cloned()
        .or_else(|| std::env::var(env).ok())
        .or_else(|| default.map(|s| s.to_owned()))
}

/// Read a passphrase from stdin when not supplied by flag/env. NOTE: this is a
/// plain (echoed) line read — a hidden-input prompt (e.g. `rpassword`) is an ops
/// hardening deferred to avoid a new dependency; the primary paths are flag/env.
fn prompt_passphrase() -> Result<Zeroizing<String>, String> {
    use std::io::Write;
    eprint!("Recovery key-blob passphrase: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("could not read passphrase: {e}"))?;
    // Trim the trailing newline only (a passphrase may legitimately contain spaces).
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(Zeroizing::new(line))
}

async fn real_main() -> Result<(), SetupExit> {
    let flags = parse_flags();

    let dial = opt(&flags, "server", "SETUP_SERVER", Some("127.0.0.1:8443")).unwrap();
    let host = opt(&flags, "host", "SETUP_HOST", Some("localhost")).unwrap();
    let out = PathBuf::from(
        opt(&flags, "out", "SETUP_OUT", None).ok_or("--out / SETUP_OUT is required")?,
    );
    let pin_out = PathBuf::from(
        opt(&flags, "pin-out", "SETUP_PIN_OUT", None)
            .ok_or("--pin-out / SETUP_PIN_OUT is required")?,
    );
    let first_key_out = PathBuf::from(
        opt(&flags, "first-key-out", "SETUP_FIRST_KEY_OUT", None)
            .ok_or("--first-key-out / SETUP_FIRST_KEY_OUT is required")?,
    );

    // Pinned server cert: explicit path, else <data-dir>/client-pins/server_cert.der
    // (exactly where the portable server writes it, like demo-seed).
    let cert_path = match opt(&flags, "cert", "SETUP_CERT", None) {
        Some(p) => PathBuf::from(p),
        None => {
            let data_dir = opt(
                &flags,
                "data-dir",
                "SETUP_DATA_DIR",
                Some("./maxsecu-server-data"),
            )
            .unwrap();
            PathBuf::from(data_dir)
                .join("client-pins")
                .join("server_cert.der")
        }
    };
    let cert_bytes = std::fs::read(&cert_path)
        .map_err(|e| format!("read pinned cert {}: {e}", cert_path.display()))?;
    let cert = CertificateDer::from(cert_bytes);

    let passphrase = match opt(&flags, "passphrase", "SETUP_RECOVERY_PW", None) {
        Some(p) => Zeroizing::new(p),
        None => prompt_passphrase()?,
    };

    let transport = Transport::new(
        pinned_client_config(cert).map_err(|e| format!("pinned client config: {}", e.message))?,
        ServerName::try_from(host.clone()).map_err(|_| "invalid --host".to_owned())?,
        dial.clone(),
    );

    eprintln!("[setup] target https://{host} (dialing {dial})");

    let opts = SetupOpts {
        host,
        out,
        pin_out,
        first_key_out,
        passphrase,
    };

    match run(&transport, &opts).await {
        Ok(report) => {
            println!();
            println!("================ MAXSECU SETUP COMPLETE ================");
            println!("recovery account registered (hybrid: {}).", report.hybrid);
            println!("  sealed recovery private key  → {}", report.out.display());
            println!(
                "  recovery pin (embed in build) → {}",
                report.pin_out.display()
            );
            println!(
                "  first registration key        → {}",
                report.first_key_out.display()
            );
            println!();
            println!("OPERATOR — do all THREE, then destroy your working copies:");
            println!(
                "  (a) MOVE {} to COLD/offline storage (it is the only recovery private key).",
                report.out.display()
            );
            println!(
                "  (b) copy {} → crates/client-app/recovery_pin.bin and REBUILD/repackage the client",
                report.pin_out.display()
            );
            println!("      so the pin is embedded (the client fails closed without it).");
            println!(
                "  (c) hand {} to the first admin (whoever enrolls with it FIRST becomes admin).",
                report.first_key_out.display()
            );
            println!("=======================================================");
            Ok(())
        }
        // Map the one "expected once-only" outcome to its typed variant; everything
        // else is a plain failure. No sentinel strings.
        Err(SetupError::AlreadyRegistered) => Err(SetupExit::AlreadyRegistered),
        Err(other) => Err(SetupExit::Failed(other.to_string())),
    }
}

/// `fetch-pins` mode (spec §4): fetch the two public trust-anchor pins from the
/// server over the network and write them ONLY if they match the operator's
/// `--fingerprint` connection code. Distinct from `real_main` (which does recovery
/// setup and consumes an already-pinned `--cert`).
async fn fetch_pins_main() -> Result<(), String> {
    let flags = parse_flags();
    let server = opt(&flags, "server", "SETUP_FETCH_SERVER", None)
        .ok_or("--server ADDR:PORT is required")?;
    // Default --host = the host part of --server (everything before the LAST colon),
    // so an `ADDR:PORT` dial target yields `ADDR` as SNI/Host.
    let default_host = server
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(server.as_str());
    let host = opt(&flags, "host", "SETUP_FETCH_HOST", Some(default_host)).unwrap();
    let fingerprint = opt(&flags, "fingerprint", "SETUP_FETCH_FINGERPRINT", None)
        .ok_or("--fingerprint is required")?;
    let cert_out =
        opt(&flags, "cert-out", "SETUP_FETCH_CERT_OUT", None).ok_or("--cert-out is required")?;
    let dir_out =
        opt(&flags, "dir-out", "SETUP_FETCH_DIR_OUT", None).ok_or("--dir-out is required")?;

    maxsecu_setup::fetch::fetch_and_verify(
        &server,
        &host,
        &fingerprint,
        std::path::Path::new(&cert_out),
        std::path::Path::new(&dir_out),
    )
    .await
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("fetch-pins") {
        return match fetch_pins_main().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(msg) => {
                eprintln!("[fetch-pins] error: {msg}");
                ExitCode::FAILURE
            }
        };
    }
    match real_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(SetupExit::AlreadyRegistered) => {
            eprintln!(
                "[setup] the server already has a recovery account registered (409). \
                 Nothing was written. This tool is one-shot; run it only against a FRESH server."
            );
            // Distinct non-zero code so scripts can tell "already done" from a fault.
            ExitCode::from(3)
        }
        Err(SetupExit::Failed(msg)) => {
            eprintln!("[setup] error: {msg}");
            ExitCode::FAILURE
        }
    }
}
