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
/// testable, no-credential path). `Dropbox` uses the real `DropboxTier` over an
/// OAuth REFRESH flow: the app key/secret + a long-lived refresh token are read
/// from the environment and auto-mint short-lived access tokens at runtime. All
/// of these secrets come from the environment and are NEVER logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdTierCfg {
    Off,
    Fs(PathBuf),
    Dropbox {
        app_key: String,
        app_secret: String,
        refresh_token: String,
        access_token: Option<String>,
        root: String,
    },
}

/// Resolved launcher configuration.
#[derive(Debug, Clone)]
pub struct LauncherConfig {
    pub data_dir: PathBuf,
    pub port: u16,
    /// Interface the listener binds to (`MAXSECU_BIND`, default `127.0.0.1`).
    /// Set to `0.0.0.0` to accept connections from the public internet.
    pub bind: String,
    /// Public IP/hostname this server is reachable at (`MAXSECU_PUBLIC_ADDR`).
    /// Host-only (any `:port` is stripped); added to the self-signed cert SAN so
    /// a client typing the bare public address passes the pinned TLS handshake.
    /// `None` keeps today's localhost-only cert.
    pub public_addr: Option<String>,
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
    /// Whether the `POST .../direct-link` endpoint (`server::http::direct_link`)
    /// brokers short-lived cloud-tier links at all. Off by default (server-proxy
    /// only) — `MAXSECU_DIRECT_LINKS=1`/`true` turns it on. Wired verbatim into
    /// `AppState.direct_links_enabled` in both profile branches (`run.rs`).
    pub direct_links_enabled: bool,
}

/// Default port for the portable server.
const DEFAULT_PORT: u16 = 8443;
/// Default data directory (relative to the launcher's working dir).
const DEFAULT_DATA_DIR: &str = "./maxsecu-server-data";
/// Default bind interface: loopback only (unreachable from the internet).
const DEFAULT_BIND: &str = "127.0.0.1";
/// Default local hot-store capacity (200 GB) before offload kicks in — leaves
/// headroom on the deployment disk for everything else.
const DEFAULT_CACHE_CAPACITY_BYTES: u64 = 200_000_000_000;
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

        // Bind interface: default loopback (unreachable from the internet); the
        // public deployment sets this to `0.0.0.0`. An empty value falls back to
        // the default rather than binding an empty (invalid) address.
        let bind = env("MAXSECU_BIND")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_BIND.to_owned());

        // Public address for the cert SAN: host or host:port; we keep host only
        // (the SAN carries no port). Empty → None (localhost-only cert).
        let public_addr = env("MAXSECU_PUBLIC_ADDR").and_then(|s| host_only(&s));

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
            Some("dropbox") => {
                // OAuth refresh flow: the app key/secret + a refresh token are all
                // required (each non-empty). Missing any one disables offload — we
                // never silently run without full credentials. The static
                // `MAXSECU_DROPBOX_TOKEN` path is gone (removed with the static mode).
                let app_key = env("MAXSECU_DROPBOX_APP_KEY").filter(|s| !s.is_empty());
                let app_secret = env("MAXSECU_DROPBOX_APP_SECRET").filter(|s| !s.is_empty());
                let refresh_token = env("MAXSECU_DROPBOX_REFRESH_TOKEN").filter(|s| !s.is_empty());
                match (app_key, app_secret, refresh_token) {
                    (Some(app_key), Some(app_secret), Some(refresh_token)) => {
                        ColdTierCfg::Dropbox {
                            app_key,
                            app_secret,
                            refresh_token,
                            // Optional pre-minted access token; empty is treated as absent.
                            access_token: env("MAXSECU_DROPBOX_ACCESS_TOKEN")
                                .filter(|s| !s.is_empty()),
                            // Normalize the root to exactly one leading '/', no
                            // trailing '/': a slashless root makes Dropbox's
                            // list_folder reject the path with a 400.
                            root: normalize_dropbox_root(
                                env("MAXSECU_DROPBOX_ROOT").as_deref().unwrap_or(""),
                            ),
                        }
                    }
                    _ => ColdTierCfg::Off,
                }
            }
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

        // Direct-link downloads: off unless explicitly turned on. Any other value
        // (absent, empty, typo) fails closed to Off, mirroring the cold-tier rule
        // above (never silently enable a feature that skips the server proxy).
        let direct_links_enabled = matches!(
            env("MAXSECU_DIRECT_LINKS").as_deref(),
            Some("1") | Some("true")
        );

        LauncherConfig {
            data_dir,
            port,
            bind,
            public_addr,
            profile,
            database_url,
            cold_tier,
            cache_capacity_bytes,
            offload_idle_days,
            direct_links_enabled,
        }
    }

    /// Thin wrapper over [`from_parts`](Self::from_parts) reading the real process
    /// environment. Wired into the launcher in Task 5.
    pub fn from_env() -> LauncherConfig {
        Self::from_parts(|k| std::env::var(k).ok())
    }
}

/// Normalize a `MAXSECU_DROPBOX_ROOT` value into a canonical Dropbox app-folder
/// root: trimmed of surrounding whitespace, exactly one leading `/`, and no
/// trailing `/`(s) (a leading `//` collapses to `/`). Dropbox's `list_folder`
/// rejects a path lacking a leading slash with a `400` (distinct from the `409`
/// for a missing folder), so a root such as `maxsecu` would 400 every upload's
/// finalize completeness check — this makes such inputs canonical. An empty or
/// whitespace-only value falls back to the default `/maxsecu`.
fn normalize_dropbox_root(raw: &str) -> String {
    let stripped = raw.trim().trim_matches('/');
    if stripped.is_empty() {
        "/maxsecu".to_owned()
    } else {
        format!("/{stripped}")
    }
}

/// Reduce a `MAXSECU_PUBLIC_ADDR` value (host or host:port) to the host only,
/// which is what a certificate SAN carries. Returns `None` for an empty value.
///
/// - a bare IP literal (v4 or v6, incl. `::1`) is returned unchanged;
/// - a bracketed IPv6 (`[::1]` or `[::1]:8443`) yields the inner address;
/// - a single trailing `:port` on a host/IPv4 is stripped;
/// - anything else (a hostname) is returned as-is.
fn host_only(addr: &str) -> Option<String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return None;
    }
    // A bare IP literal (including multi-colon IPv6) is kept verbatim.
    if addr.parse::<std::net::IpAddr>().is_ok() {
        return Some(addr.to_owned());
    }
    // Bracketed IPv6, with or without a port: take the address inside the brackets.
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return Some(rest[..end].to_owned());
        }
    }
    // host:port (a single colon, i.e. hostname or IPv4 with a port) → strip the port.
    if let Some((host, _port)) = addr.rsplit_once(':') {
        if !host.is_empty() && !host.contains(':') {
            return Some(host.to_owned());
        }
    }
    Some(addr.to_owned())
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
    fn bind_defaults_to_loopback_and_honors_explicit_value() {
        // Default: loopback only.
        assert_eq!(LauncherConfig::from_parts(env(&[])).bind, "127.0.0.1");
        // Explicit public bind.
        assert_eq!(
            LauncherConfig::from_parts(env(&[("MAXSECU_BIND", "0.0.0.0")])).bind,
            "0.0.0.0"
        );
        // Empty falls back to the default (never binds an empty address).
        assert_eq!(
            LauncherConfig::from_parts(env(&[("MAXSECU_BIND", "")])).bind,
            "127.0.0.1"
        );
    }

    #[test]
    fn public_addr_is_none_by_default_and_host_only_when_set() {
        // Absent → None (localhost-only cert, today's behavior).
        assert_eq!(LauncherConfig::from_parts(env(&[])).public_addr, None);
        // Empty → None.
        assert_eq!(
            LauncherConfig::from_parts(env(&[("MAXSECU_PUBLIC_ADDR", "")])).public_addr,
            None
        );
        // A bare IP is kept as-is.
        assert_eq!(
            LauncherConfig::from_parts(env(&[("MAXSECU_PUBLIC_ADDR", "1.2.3.4")])).public_addr,
            Some("1.2.3.4".to_owned())
        );
        // ip:port → the port is stripped (SAN is host-only).
        assert_eq!(
            LauncherConfig::from_parts(env(&[("MAXSECU_PUBLIC_ADDR", "1.2.3.4:8443")])).public_addr,
            Some("1.2.3.4".to_owned())
        );
        // host:port → the port is stripped, hostname preserved.
        assert_eq!(
            LauncherConfig::from_parts(env(&[("MAXSECU_PUBLIC_ADDR", "vps.example.com:8443")]))
                .public_addr,
            Some("vps.example.com".to_owned())
        );
    }

    #[test]
    fn cold_tier_defaults_off_with_sane_capacity_and_idle() {
        let c = LauncherConfig::from_parts(env(&[]));
        assert_eq!(c.cold_tier, ColdTierCfg::Off);
        assert_eq!(c.cache_capacity_bytes, 200_000_000_000);
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
    fn cold_tier_dropbox_needs_full_refresh_credentials() {
        // Full set (all three required + optional access token + explicit root).
        let ok = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "dropbox"),
            ("MAXSECU_DROPBOX_APP_KEY", "key"),
            ("MAXSECU_DROPBOX_APP_SECRET", "secret"),
            ("MAXSECU_DROPBOX_REFRESH_TOKEN", "refresh"),
            ("MAXSECU_DROPBOX_ACCESS_TOKEN", "access"),
            ("MAXSECU_DROPBOX_ROOT", "/mx"),
        ]));
        assert_eq!(
            ok.cold_tier,
            ColdTierCfg::Dropbox {
                app_key: "key".to_owned(),
                app_secret: "secret".to_owned(),
                refresh_token: "refresh".to_owned(),
                access_token: Some("access".to_owned()),
                root: "/mx".to_owned(),
            }
        );

        // Each of the three required vars is individually mandatory; missing any
        // one fails closed to Off (never runs without full credentials).
        let missing_app_key = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "dropbox"),
            ("MAXSECU_DROPBOX_APP_SECRET", "secret"),
            ("MAXSECU_DROPBOX_REFRESH_TOKEN", "refresh"),
        ]));
        assert_eq!(missing_app_key.cold_tier, ColdTierCfg::Off);
        let missing_app_secret = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "dropbox"),
            ("MAXSECU_DROPBOX_APP_KEY", "key"),
            ("MAXSECU_DROPBOX_REFRESH_TOKEN", "refresh"),
        ]));
        assert_eq!(missing_app_secret.cold_tier, ColdTierCfg::Off);
        let missing_refresh = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "dropbox"),
            ("MAXSECU_DROPBOX_APP_KEY", "key"),
            ("MAXSECU_DROPBOX_APP_SECRET", "secret"),
        ]));
        assert_eq!(missing_refresh.cold_tier, ColdTierCfg::Off);

        // A present-but-empty required var also fails closed to Off.
        let empty_required = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "dropbox"),
            ("MAXSECU_DROPBOX_APP_KEY", "key"),
            ("MAXSECU_DROPBOX_APP_SECRET", ""),
            ("MAXSECU_DROPBOX_REFRESH_TOKEN", "refresh"),
        ]));
        assert_eq!(empty_required.cold_tier, ColdTierCfg::Off);

        // Bare full required set: root defaults to `/maxsecu`, access token None.
        let defaults = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "dropbox"),
            ("MAXSECU_DROPBOX_APP_KEY", "key"),
            ("MAXSECU_DROPBOX_APP_SECRET", "secret"),
            ("MAXSECU_DROPBOX_REFRESH_TOKEN", "refresh"),
        ]));
        assert_eq!(
            defaults.cold_tier,
            ColdTierCfg::Dropbox {
                app_key: "key".to_owned(),
                app_secret: "secret".to_owned(),
                refresh_token: "refresh".to_owned(),
                access_token: None,
                root: "/maxsecu".to_owned(),
            }
        );
    }

    #[test]
    fn dropbox_root_is_normalized_to_a_single_leading_slash() {
        // Every one of these variants must normalize to the same `/maxsecu`.
        for raw in [
            "maxsecu",
            "/maxsecu/",
            "maxsecu/",
            "//maxsecu",
            "  /maxsecu  ",
            "/maxsecu",
        ] {
            let c = LauncherConfig::from_parts(env(&[
                ("MAXSECU_COLD_TIER", "dropbox"),
                ("MAXSECU_DROPBOX_APP_KEY", "key"),
                ("MAXSECU_DROPBOX_APP_SECRET", "secret"),
                ("MAXSECU_DROPBOX_REFRESH_TOKEN", "refresh"),
                ("MAXSECU_DROPBOX_ROOT", raw),
            ]));
            match c.cold_tier {
                ColdTierCfg::Dropbox { root, .. } => {
                    assert_eq!(root, "/maxsecu", "root {raw:?} must normalize to /maxsecu")
                }
                other => panic!("expected Dropbox cold tier, got {other:?}"),
            }
        }

        // An empty / whitespace-only root falls back to the default `/maxsecu`.
        for raw in ["", "   ", "/"] {
            let c = LauncherConfig::from_parts(env(&[
                ("MAXSECU_COLD_TIER", "dropbox"),
                ("MAXSECU_DROPBOX_APP_KEY", "key"),
                ("MAXSECU_DROPBOX_APP_SECRET", "secret"),
                ("MAXSECU_DROPBOX_REFRESH_TOKEN", "refresh"),
                ("MAXSECU_DROPBOX_ROOT", raw),
            ]));
            match c.cold_tier {
                ColdTierCfg::Dropbox { root, .. } => {
                    assert_eq!(root, "/maxsecu", "root {raw:?} must default to /maxsecu")
                }
                other => panic!("expected Dropbox cold tier, got {other:?}"),
            }
        }

        // A nested root keeps its interior slashes, gains a single leading slash,
        // loses trailing slashes.
        assert_eq!(normalize_dropbox_root("app/data/"), "/app/data");
        assert_eq!(normalize_dropbox_root("///a//"), "/a");
    }

    #[test]
    fn unknown_cold_tier_and_zero_capacity_fall_back() {
        let c = LauncherConfig::from_parts(env(&[
            ("MAXSECU_COLD_TIER", "s3"),
            ("MAXSECU_CACHE_CAPACITY_BYTES", "0"),
        ]));
        assert_eq!(c.cold_tier, ColdTierCfg::Off);
        assert_eq!(c.cache_capacity_bytes, 200_000_000_000); // 0 rejected → default
    }

    #[test]
    fn direct_links_default_off_and_only_explicit_1_or_true_turn_it_on() {
        // Default (env absent) — off.
        assert!(!LauncherConfig::from_parts(env(&[])).direct_links_enabled);
        // Explicit "1" and "true" — on.
        assert!(
            LauncherConfig::from_parts(env(&[("MAXSECU_DIRECT_LINKS", "1")])).direct_links_enabled
        );
        assert!(
            LauncherConfig::from_parts(env(&[("MAXSECU_DIRECT_LINKS", "true")]))
                .direct_links_enabled
        );
        // Anything else (typo, "0", "false", empty) fails closed to off.
        for v in ["0", "false", "yes", "TRUE", ""] {
            assert!(
                !LauncherConfig::from_parts(env(&[("MAXSECU_DIRECT_LINKS", v)]))
                    .direct_links_enabled,
                "value {v:?} must not enable direct links"
            );
        }
    }
}
