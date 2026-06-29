//! MaxSecu portable server launcher (spec §8.2). Lays out a portable folder,
//! generates a DEV self-signed pinned cert + bootstrap secret + DEV D5 key, and
//! serves the secret-free server over TLS. The DEV profile runs with no external
//! deps (MemoryStore + FsBlobStore); PROD parity (Postgres + injected cert/sink)
//! is behind a config flag. The DEV D5/secret are SECURITY-DEGRADED — never a
//! production ceremony key.
#![forbid(unsafe_code)]

mod bootstrap;
mod config;
mod layout;
mod pki;
mod run;

fn main() -> std::io::Result<()> {
    let cfg = config::LauncherConfig::from_env();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run::run(cfg))
}
