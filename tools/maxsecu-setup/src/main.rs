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
//!
//! Offline-D5 ceremony (spec §7) — ACTIVATED by supplying a delegation token:
//!   --delegation-token / SETUP_DELEGATION_TOKEN  one-time bootstrap token (enables
//!                                                the ceremony; absent → legacy path)
//!   --connect-addr / SETUP_CONNECT_ADDR   addr:port the connection code advertises
//!                                         (default: the --server dial target)
//!   --d5-out / SETUP_D5_OUT               sealed at-rest D5 (default <out-dir>/d5_key.blob)
//!   --d5-recovery-out / SETUP_D5_RECOVERY_OUT  D5 backup, SAME passphrase
//!                                         (default <out-dir>/d5_recovery.blob)
//!   --dir-pub-out / SETUP_DIR_PUB_OUT     local directory_pub.der pin
//!                                         (default <out-dir>/directory_pub.der)
//!
//! Subcommands (argv[1]): `fetch-pins` (cert-only or 2-pin), `restore` (rebuild the
//! D5 custody + connection code from a `d5_recovery.blob` backup — see `restore_main`).

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
    let cert = CertificateDer::from(cert_bytes.clone());

    let passphrase = match opt(&flags, "passphrase", "SETUP_RECOVERY_PW", None) {
        Some(p) => Zeroizing::new(p),
        None => prompt_passphrase()?,
    };

    // Offline-D5 ceremony (spec §7). ACTIVATED when a one-time delegation token is
    // supplied (`--delegation-token` / SETUP_DELEGATION_TOKEN); absent → legacy
    // recovery-only bootstrap. The three D5 custody paths default alongside `--out`.
    let ceremony = match opt(&flags, "delegation-token", "SETUP_DELEGATION_TOKEN", None) {
        Some(tok) if !tok.trim().is_empty() => {
            let out_dir = out.parent().map(PathBuf::from).unwrap_or_default();
            let d5_out = PathBuf::from(
                opt(&flags, "d5-out", "SETUP_D5_OUT", None)
                    .unwrap_or_else(|| out_dir.join("d5_key.blob").to_string_lossy().into_owned()),
            );
            let d5_recovery_out = PathBuf::from(
                opt(&flags, "d5-recovery-out", "SETUP_D5_RECOVERY_OUT", None).unwrap_or_else(
                    || {
                        out_dir
                            .join("d5_recovery.blob")
                            .to_string_lossy()
                            .into_owned()
                    },
                ),
            );
            let dir_pub_out = PathBuf::from(
                opt(&flags, "dir-pub-out", "SETUP_DIR_PUB_OUT", None).unwrap_or_else(|| {
                    out_dir
                        .join("directory_pub.der")
                        .to_string_lossy()
                        .into_owned()
                }),
            );
            // The connection code advertises this addr:port (defaults to the dial
            // target; override when the public address differs, e.g. a port map).
            let connect_addr = opt(
                &flags,
                "connect-addr",
                "SETUP_CONNECT_ADDR",
                Some(dial.as_str()),
            )
            .unwrap();
            Some(maxsecu_setup::CeremonyOpts {
                token: Zeroizing::new(tok),
                server_cert: cert_bytes,
                connect_addr,
                d5_out,
                d5_recovery_out,
                dir_pub_out,
            })
        }
        _ => None,
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
        ceremony,
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
            if let Some(cer) = &report.ceremony {
                println!();
                println!("OFFLINE-D5 DELEGATION installed (directory root held on THIS PC):");
                println!("  sealed D5 root (at rest)      → {}", cer.d5_out.display());
                println!(
                    "  D5 recovery backup            → {}",
                    cer.d5_recovery_out.display()
                );
                println!(
                    "  directory pin (client trusts) → {}",
                    cer.dir_pub_out.display()
                );
                println!("  delegation valid until (unix) → {}", cer.valid_until);
                println!();
                println!(
                    "  (d) MOVE {} to COLD/offline storage WITH the recovery blob — it is the",
                    cer.d5_recovery_out.display()
                );
                println!(
                    "      directory root; the same passphrase restores it (no client re-pin)."
                );
                println!();
                // Machine-parseable line for install-client.ps1 to surface the code.
                println!("CONNECTION-CODE {}", cer.connection_code);
            }
            println!("=======================================================");
            Ok(())
        }
        // Map the "expected once-only / already-done" outcomes to their typed exit;
        // everything else is a plain failure. No sentinel strings.
        Err(SetupError::AlreadyRegistered) => Err(SetupExit::AlreadyRegistered),
        Err(SetupError::AlreadyDelegated) => Err(SetupExit::AlreadyRegistered),
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
    // `--dir-out` is OPTIONAL: when supplied → 2-pin mode (verify + write both);
    // when omitted → cert-only mode (offline-D5 ceremony, server awaiting): verify
    // pin_fingerprint(cert, &[]) against the cert fingerprint and write only the cert.
    let dir_out = opt(&flags, "dir-out", "SETUP_FETCH_DIR_OUT", None);

    maxsecu_setup::fetch::fetch_and_verify(
        &server,
        &host,
        &fingerprint,
        std::path::Path::new(&cert_out),
        dir_out.as_deref().map(std::path::Path::new),
    )
    .await
}

/// `restore` mode (spec §7): rebuild the offline-D5 custody + connection code on a
/// NEW admin PC from the `d5_recovery.blob` backup, using the recovery passphrase.
/// No network, no delegation upload — the server already holds a delegation for this
/// exact D5 (the SAME directory root), so no client re-pins.
///
/// Flags / env (all via arg/env for unattended use):
///   --d5-recovery-in / SETUP_D5_RECOVERY_IN   the backup blob to restore (required)
///   --cert / SETUP_CERT (or --data-dir)       pinned server_cert.der (for the code)
///   --connect-addr / SETUP_CONNECT_ADDR       addr:port the code advertises (required)
///   --d5-out / SETUP_D5_OUT                    re-sealed at-rest d5_key.blob (required)
///   --dir-pub-out / SETUP_DIR_PUB_OUT         local directory_pub.der pin (required)
///   --passphrase / SETUP_RECOVERY_PW          the recovery passphrase (else prompted)
async fn restore_main() -> Result<(), String> {
    let flags = parse_flags();
    let d5_recovery_in = PathBuf::from(
        opt(&flags, "d5-recovery-in", "SETUP_D5_RECOVERY_IN", None)
            .ok_or("--d5-recovery-in / SETUP_D5_RECOVERY_IN is required")?,
    );
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
    let server_cert = std::fs::read(&cert_path)
        .map_err(|e| format!("read pinned cert {}: {e}", cert_path.display()))?;
    let connect_addr = opt(&flags, "connect-addr", "SETUP_CONNECT_ADDR", None)
        .ok_or("--connect-addr / SETUP_CONNECT_ADDR is required")?;
    let d5_out = PathBuf::from(
        opt(&flags, "d5-out", "SETUP_D5_OUT", None).ok_or("--d5-out / SETUP_D5_OUT is required")?,
    );
    let dir_pub_out = PathBuf::from(
        opt(&flags, "dir-pub-out", "SETUP_DIR_PUB_OUT", None)
            .ok_or("--dir-pub-out / SETUP_DIR_PUB_OUT is required")?,
    );
    let passphrase = match opt(&flags, "passphrase", "SETUP_RECOVERY_PW", None) {
        Some(p) => Zeroizing::new(p),
        None => prompt_passphrase()?,
    };

    let opts = maxsecu_setup::RestoreOpts {
        passphrase,
        d5_recovery_in,
        server_cert,
        connect_addr,
        d5_out,
        dir_pub_out,
    };
    let report = maxsecu_setup::restore(&opts).map_err(|e| e.to_string())?;
    println!();
    println!("================ MAXSECU D5 RESTORE COMPLETE ================");
    println!(
        "  re-sealed D5 root (at rest)   → {}",
        report.d5_out.display()
    );
    println!(
        "  directory pin (client trusts) → {}",
        report.dir_pub_out.display()
    );
    println!("  (same directory root — no client needs to re-pin.)");
    println!("CONNECTION-CODE {}", report.connection_code);
    println!("============================================================");
    Ok(())
}

/// `renew-delegation` mode (spec §7 "Manual fallback"): the robust, unattended
/// renewal path. Unseal the admin PC's D5 root + recovery key (both under the
/// recovery passphrase), recovery-login for an admin session, and — when the
/// current delegation is within the 21-day threshold (or `--force`) — sign a fresh
/// 90-day delegation for the server's current operational key and push it via
/// `POST /v1/admin/delegation`. A not-due run is a clean no-op (exit 0). Fail-closed
/// and non-destructive: a fault exits non-zero but corrupts nothing on disk.
///
/// Flags / env:
///   --server / SETUP_SERVER        TCP dial target          (default 127.0.0.1:8443)
///   --host   / SETUP_HOST          cert SAN / SNI / Host     (default localhost)
///   --cert / SETUP_CERT (or --data-dir)   pinned server_cert.der (like `real_main`)
///   --d5-in / SETUP_D5_IN          sealed D5 root            (default d5_key.blob)
///   --recovery-in / SETUP_RECOVERY_IN  sealed recovery key blob (default recovery_key.blob)
///   --passphrase / SETUP_RECOVERY_PW   recovery passphrase (unseals both; else prompted)
///   --force / SETUP_FORCE          renew regardless of the 21-day threshold
async fn renew_main() -> Result<(), String> {
    let flags = parse_flags();
    let dial = opt(&flags, "server", "SETUP_SERVER", Some("127.0.0.1:8443")).unwrap();
    let host = opt(&flags, "host", "SETUP_HOST", Some("localhost")).unwrap();
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
    let d5_in = PathBuf::from(opt(&flags, "d5-in", "SETUP_D5_IN", Some("d5_key.blob")).unwrap());
    let recovery_in = PathBuf::from(
        opt(
            &flags,
            "recovery-in",
            "SETUP_RECOVERY_IN",
            Some("recovery_key.blob"),
        )
        .unwrap(),
    );
    // `--force` is a bare flag (parse_flags stores it with an empty value) OR
    // SETUP_FORCE=1; any present-and-non-"0"/"false" value enables it.
    let force = match opt(&flags, "force", "SETUP_FORCE", None) {
        Some(v) => {
            let v = v.trim();
            v.is_empty() || !matches!(v, "0" | "false" | "no")
        }
        None => false,
    };
    let passphrase = match opt(&flags, "passphrase", "SETUP_RECOVERY_PW", None) {
        Some(p) => Zeroizing::new(p),
        None => prompt_passphrase()?,
    };

    let transport = Transport::new(
        pinned_client_config(cert).map_err(|e| format!("pinned client config: {}", e.message))?,
        ServerName::try_from(host.clone()).map_err(|_| "invalid --host".to_owned())?,
        dial.clone(),
    );
    eprintln!("[renew] target https://{host} (dialing {dial})");

    let opts = maxsecu_setup::RenewOpts {
        host,
        passphrase,
        d5_in,
        recovery_in,
        force,
    };
    match maxsecu_setup::renew(&transport, &opts)
        .await
        .map_err(|e| e.to_string())?
    {
        maxsecu_setup::RenewOutcome::NotDue { valid_until } => {
            println!("not due (valid until {valid_until})");
        }
        maxsecu_setup::RenewOutcome::Renewed { valid_until } => {
            println!("renewed (valid until {valid_until})");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("renew-delegation") {
        return match renew_main().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(msg) => {
                eprintln!("[renew] error: {msg}");
                ExitCode::FAILURE
            }
        };
    }
    if std::env::args().nth(1).as_deref() == Some("fetch-pins") {
        return match fetch_pins_main().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(msg) => {
                eprintln!("[fetch-pins] error: {msg}");
                ExitCode::FAILURE
            }
        };
    }
    if std::env::args().nth(1).as_deref() == Some("restore") {
        return match restore_main().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(msg) => {
                eprintln!("[restore] error: {msg}");
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
