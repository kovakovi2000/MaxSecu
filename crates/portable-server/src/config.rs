//! Launcher configuration (Phase-6 Task 2). Resolves the runtime profile and
//! paths/ports from the environment. `from_parts` is pure (takes an env lookup
//! closure) so it is testable without touching the real process environment.
// Wired into the launcher in Task 5; until then these items are exercised only
// by the unit tests, so the non-test bin build sees them as dead.
#![allow(dead_code)]

use std::path::PathBuf;

/// Runtime profile. `Dev` runs with no external deps (MemoryStore + FsBlobStore);
/// `Prod` is selected when a `DATABASE_URL` is present (Postgres-backed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    Dev,
    Prod,
}

/// Resolved launcher configuration.
#[derive(Debug, Clone)]
pub struct LauncherConfig {
    pub data_dir: PathBuf,
    pub port: u16,
    pub profile: Profile,
    pub database_url: Option<String>,
}

/// Default port for the portable server.
const DEFAULT_PORT: u16 = 8443;
/// Default data directory (relative to the launcher's working dir).
const DEFAULT_DATA_DIR: &str = "./maxsecu-server-data";

impl LauncherConfig {
    /// Pure resolver: builds the config from an env-lookup closure. Rules:
    /// - `data_dir` = `MAXSECU_DATA_DIR` or `./maxsecu-server-data`
    /// - `port` = `MAXSECU_PORT` parsed, falling back to `8443` on absence/parse error
    /// - `database_url` = `DATABASE_URL` (Some → `Prod`, None → `Dev`)
    pub fn from_parts(env: impl Fn(&str) -> Option<String>) -> LauncherConfig {
        let data_dir = env("MAXSECU_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));

        let port = env("MAXSECU_PORT")
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(DEFAULT_PORT);

        let database_url = env("DATABASE_URL");
        let profile = if database_url.is_some() {
            Profile::Prod
        } else {
            Profile::Dev
        };

        LauncherConfig {
            data_dir,
            port,
            profile,
            database_url,
        }
    }

    /// Thin wrapper over [`from_parts`](Self::from_parts) reading the real process
    /// environment. Wired into the launcher in Task 5.
    pub fn from_env() -> LauncherConfig {
        Self::from_parts(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    fn env<'a>(map: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let m: HashMap<&str, &str> = map.iter().copied().collect();
        move |k| m.get(k).map(|v| v.to_string())
    }
    #[test]
    fn defaults_to_dev_when_no_database_url() {
        let c = LauncherConfig::from_parts(env(&[]));
        assert_eq!(c.profile, Profile::Dev);
        assert_eq!(c.port, 8443);
        assert!(c.database_url.is_none());
    }
    #[test]
    fn prod_when_database_url_set_and_port_parsed() {
        let c = LauncherConfig::from_parts(env(&[
            ("DATABASE_URL", "postgres://x"),
            ("MAXSECU_PORT", "9000"),
        ]));
        assert_eq!(c.profile, Profile::Prod);
        assert_eq!(c.port, 9000);
        assert_eq!(c.database_url.as_deref(), Some("postgres://x"));
    }
    #[test]
    fn bad_port_falls_back_to_default() {
        let c = LauncherConfig::from_parts(env(&[("MAXSECU_PORT", "not-a-number")]));
        assert_eq!(c.port, 8443);
    }
}
