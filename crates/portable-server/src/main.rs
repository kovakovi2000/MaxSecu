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
    let cfg = LauncherConfig::from_env();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run::run(cfg))
}
