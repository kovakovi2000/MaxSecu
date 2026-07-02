//! Launcher configuration (Phase-6 Task 2). Resolves the runtime profile and
//! paths/ports from the environment. `from_parts` is pure (takes an env lookup
//! closure) so it is testable without touching the real process environment.
use std::path::PathBuf;

/// Runtime profile. `Dev` runs with no external deps (MemoryStore + FsBlobStore);
/// `Prod` is selected when a `DATABASE_URL` is present (Postgres-backed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    Dev,
    Prod,
}

/// Cold-tier backing for the write-back offload engine (`server::writeback_tier`).
/// `Off` keeps today's behavior (a plain local `FsBlobStore`, no offload). `Fs`
/// backs the cold tier with an on-disk `FsColdTier` (models Dropbox locally — the
/// testable, no-credential path). `Dropbox` uses the real `DropboxTier` (OAuth
/// token from the environment, NEVER logged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdTierCfg {
    Off,
    Fs(PathBuf),
    Dropbox { token: String, root: String },
}

/// Resolved launcher configuration.
#[derive(Debug, Clone)]
pub struct LauncherConfig {
    pub data_dir: PathBuf,
    pub port: u16,
    pub profile: Profile,
    pub database_url: Option<String>,
    /// The cold tier the write-back offload engine migrates idle/evicted chunks to.
    pub cold_tier: ColdTierCfg,
    /// Local hot-store byte budget; once exceeded, LRU chunks are offloaded to the
    /// cold tier to make room (on both upload and download).
    pub cache_capacity_bytes: u64,
    /// Not-requested-for span after which a chunk is offloaded by the background
    /// idle sweep, in whole days.
    pub offload_idle_days: u64,
}

/// Default port for the portable server.
const DEFAULT_PORT: u16 = 8443;
/// Default data directory (relative to the launcher's working dir).
const DEFAULT_DATA_DIR: &str = "./maxsecu-server-data";
/// Default local hot-store capacity (250 GB) before offload kicks in.
const DEFAULT_CACHE_CAPACITY_BYTES: u64 = 250_000_000_000;
/// Default idle span (30 days) before a cold chunk is offloaded.
const DEFAULT_OFFLOAD_IDLE_DAYS: u64 = 30;

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

        // Cold tier: `off` (default) | `fs` | `dropbox`. An unknown/malformed value
        // fails closed to `Off` (no offload) rather than guessing.
        let cold_tier = match env("MAXSECU_COLD_TIER").as_deref() {
            Some("fs") => {
                let dir = env("MAXSECU_COLD_FS_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| data_dir.join("cold"));
                ColdTierCfg::Fs(dir)
            }
            Some("dropbox") => match (env("MAXSECU_DROPBOX_TOKEN"), env("MAXSECU_DROPBOX_ROOT")) {
                // Both the token and a root are required; missing either disables
                // offload (never silently runs without a destination).
                (Some(token), root) if !token.is_empty() => ColdTierCfg::Dropbox {
                    token,
                    root: root.unwrap_or_else(|| "/maxsecu".to_owned()),
                },
                _ => ColdTierCfg::Off,
            },
            _ => ColdTierCfg::Off,
        };

        let cache_capacity_bytes = env("MAXSECU_CACHE_CAPACITY_BYTES")
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_CACHE_CAPACITY_BYTES);

        let offload_idle_days = env("MAXSECU_OFFLOAD_IDLE_DAYS")
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_OFFLOAD_IDLE_DAYS);

        LauncherConfig {
            data_dir,
            port,
            profile,
            database_url,
            cold_tier,
            cache_capacity_bytes,
            offload_idle_days,
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

    #[test]
    fn cold_tier_defaults_off_with_sane_capacity_and_idle() {
        let c = LauncherConfig::from_parts(env(&[]));
        assert_eq!(c.cold_tier, ColdTierCfg::Off);
        assert_eq!(c.cache_capacity_bytes, 250_000_000_000);
        assert_eq!(c.offload_idle_days, 30);
    }

    #[test]
    fn cold_tier_fs_uses_configured_dir_and_overrides() {
        let c = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "fs"),
            ("MAXSECU_COLD_FS_DIR", "/srv/cold"),
            ("MAXSECU_CACHE_CAPACITY_BYTES", "1024"),
            ("MAXSECU_OFFLOAD_IDLE_DAYS", "7"),
        ]));
        assert_eq!(c.cold_tier, ColdTierCfg::Fs(PathBuf::from("/srv/cold")));
        assert_eq!(c.cache_capacity_bytes, 1024);
        assert_eq!(c.offload_idle_days, 7);
    }

    #[test]
    fn cold_tier_dropbox_needs_a_nonempty_token() {
        let ok = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "dropbox"),
            ("MAXSECU_DROPBOX_TOKEN", "tok"),
            ("MAXSECU_DROPBOX_ROOT", "/mx"),
        ]));
        assert_eq!(
            ok.cold_tier,
            ColdTierCfg::Dropbox {
                token: "tok".to_owned(),
                root: "/mx".to_owned()
            }
        );
        // Missing/empty token → fails closed to Off (never runs without a token).
        let missing =
            LauncherConfig::from_parts(env(&[("MAXSECU_COLD_TIER", "dropbox")]));
        assert_eq!(missing.cold_tier, ColdTierCfg::Off);
    }

    #[test]
    fn unknown_cold_tier_and_zero_capacity_fall_back() {
        let c = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "s3"),
            ("MAXSECU_CACHE_CAPACITY_BYTES", "0"),
        ]));
        assert_eq!(c.cold_tier, ColdTierCfg::Off);
        assert_eq!(c.cache_capacity_bytes, 250_000_000_000); // 0 rejected → default
    }
}
