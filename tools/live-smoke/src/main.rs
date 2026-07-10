//! Headless functional oracle for the full-install E2E harness. Drives the REAL
//! client-core/client-app code paths against a LIVE installed MaxSecu server over
//! the pinned TLS transport. Any failed assertion returns Err → process exit 1.
//!
//! Usage:
//!   maxsecu-live-smoke --server <ip:port> --host <ip> --client-dir <dist/MaxSecuClient>
//!
//! --server      dial target ip:port (the WSL server's --public address)
//! --host        the cert-SAN name to verify against == the public IP (same as --server host)
//! --client-dir  the built admin client dir: reads config/server_cert.der,
//!               config/directory_pub.der, and register.key (the admin's first key)

mod net;
mod steps;

use std::process::ExitCode;

struct Args {
    server: String,
    host: String,
    client_dir: std::path::PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut server = None;
    let mut host = None;
    let mut client_dir = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--server" => server = it.next(),
            "--host" => host = it.next(),
            "--client-dir" => client_dir = it.next(),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        server: server.ok_or("missing --server")?,
        host: host.ok_or("missing --host")?,
        client_dir: client_dir.ok_or("missing --client-dir")?.into(),
    })
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
    match steps::run(&args.server, &args.host, &args.client_dir).await {
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
