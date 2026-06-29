//! MaxSecu portable server launcher (spec §8.2). Lays out a portable folder,
//! generates a DEV self-signed pinned cert + bootstrap secret + DEV D5 key, and
//! serves the secret-free server over TLS. The DEV profile runs with no external
//! deps (MemoryStore + FsBlobStore); PROD parity (Postgres + injected cert/sink)
//! is behind a config flag. The DEV D5/secret are SECURITY-DEGRADED — never a
//! production ceremony key.
#![forbid(unsafe_code)]

mod config;
mod layout;

fn main() {
    eprintln!("maxsecu-portable-server: starting…");
    // Launcher logic is wired up across Phase-6 Tasks 2–7.
}
