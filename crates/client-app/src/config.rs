//! ConnectionConfig: where to connect and whether to auto-connect. The test
//! build ships an auto-connect config (spec §4.4); the "later" build leaves
//! `auto_connect=false` and the user types the server on the connect screen.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::UiError;

/// Load the pinned offline **directory-signing (D5) public key** (§7.3) from
/// `<dir>/config/directory_pub.der` (32 raw bytes). The trust root the client
/// verifies every served binding against; absent or malformed ⇒ fail closed with
/// a sanitized `untrusted` error (no browse/admin without a pinned root). Mirrors
/// the pinned server-cert source used by `commands::connection::open_conn`.
pub fn load_directory_pub(dir: &Path) -> Result<[u8; 32], UiError> {
    let path = dir.join("config").join("directory_pub.der");
    let bytes = std::fs::read(&path)
        .map_err(|_| UiError::new("untrusted", "This server's directory key is not pinned."))?;
    bytes
        .try_into()
        .map_err(|_| UiError::new("untrusted", "The pinned directory key is malformed."))
}

/// The configured standing **recovery recipient** username (`<dir>/config/
/// recovery_recipient.txt`, one line, trimmed). The upload resolves its
/// directory-verified `enc_pub` as the mandatory recovery wrap target (DESIGN §6.3).
pub fn recovery_recipient_username(dir: &Path) -> Result<String, UiError> {
    let path = dir.join("config").join("recovery_recipient.txt");
    let raw = std::fs::read_to_string(&path).map_err(|_| {
        UiError::new(
            "no_recovery_recipient",
            "No recovery recipient is configured.",
        )
    })?;
    let name = raw.trim();
    if name.is_empty() {
        return Err(UiError::new(
            "no_recovery_recipient",
            "No recovery recipient is configured.",
        ));
    }
    Ok(name.to_owned())
}

// Loaded by the UI in a later phase (Task 10) to prefill the connect form /
// drive auto-connect; Phase-1 `connect` takes its parameters straight from the
// ConnectRequest, so this type is not yet read by the binary.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConnectionConfig {
    pub server: String,
    pub use_tor: bool,
    pub auto_connect: bool,
}

#[allow(dead_code)] // load/save wired by the UI in Task 10 (see type comment).
impl ConnectionConfig {
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join("config").join("connection.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let p = dir.join("config");
        std::fs::create_dir_all(&p)?;
        std::fs::write(
            p.join("connection.json"),
            serde_json::to_vec_pretty(self).unwrap(),
        )
    }
}

// Local preferences store (no secret material — safe in cleartext at
// `<dir>/config/settings.json`). Per-section `#[serde(default)]` lets a partial
// or older file still load; `normalized()` clamps untrusted (hand-edited) values.
// Wired into get/set commands in Phase-5 Task 2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct A11ySettings {
    pub reduced_motion: bool,
    pub high_contrast: bool,
    pub text_size: String,
}
impl Default for A11ySettings {
    fn default() -> Self {
        Self {
            reduced_motion: false,
            high_contrast: false,
            text_size: "normal".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BehaviorSettings {
    pub confirm_destructive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PerformanceSettings {
    pub ram_cache_cap_mb: u32,
}
impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            ram_cache_cap_mb: 256,
        }
    }
}

/// The download/transport **route** the client uses (3-way, spec
/// `2026-07-02-download-route-setting`). The connect-screen "Route through Tor"
/// checkbox is the boolean face of this: ticking it selects (and persists)
/// [`RouteMode::TorOnly`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RouteMode {
    /// Route ALL traffic over Tor; fail closed (never a clearnet fallback). Forces
    /// server-proxy (direct-Dropbox links are disabled under Tor).
    TorOnly,
    /// The server proxies every blob (default — today's behavior).
    #[default]
    PreferServer,
    /// Download an offloaded blob's ciphertext DIRECTLY from Dropbox via a
    /// server-brokered short-lived link when available; else the server proxies.
    /// Every fetched byte is still AEAD/manifest-verified, so a tampering link is
    /// caught (the link source is untrusted).
    PreferDropbox,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConnectionSettings {
    /// The authoritative route selection.
    #[serde(default)]
    pub route_mode: RouteMode,
    /// Legacy pre-3-way boolean. Kept only for back-compat read/write of older
    /// `settings.json`; `route_mode` is authoritative. `normalized()` migrates a
    /// legacy `use_tor=true` (with no explicit `route_mode`) into `TorOnly`, and
    /// keeps this field in sync with `route_mode` on every save.
    #[serde(default)]
    pub use_tor: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppearanceSettings {
    /// "dark" (default) | "light". Applied via `<html data-theme>` in the UI.
    pub theme: String,
}
impl Default for AppearanceSettings {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SettingsConfig {
    #[serde(default)]
    pub a11y: A11ySettings,
    #[serde(default)]
    pub behavior: BehaviorSettings,
    #[serde(default)]
    pub performance: PerformanceSettings,
    #[serde(default)]
    pub connection: ConnectionSettings,
    #[serde(default)]
    pub appearance: AppearanceSettings,
}

impl SettingsConfig {
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join("config").join("settings.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .map(|s: SettingsConfig| s.normalized())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let p = dir.join("config");
        std::fs::create_dir_all(&p)?;
        std::fs::write(
            p.join("settings.json"),
            serde_json::to_vec_pretty(&self.normalized()).unwrap(),
        )
    }

    /// Clamp/normalize untrusted values using the live RAM bounds. Convenience
    /// wrapper that reads the system RAM; the pure work is `normalized_with_ram`.
    pub fn normalized(&self) -> SettingsConfig {
        let limits = crate::ram::compute_ram_limits(crate::ram::system_total_mb_public());
        self.normalized_with_ram(&limits)
    }

    /// Pure normalization against explicit RAM bounds (unit-testable): clamp the
    /// RAM cache cap into [min,max], constrain text_size + theme to known sets.
    pub fn normalized_with_ram(&self, limits: &crate::ram::RamLimits) -> SettingsConfig {
        let mut s = self.clone();
        s.performance.ram_cache_cap_mb = s
            .performance
            .ram_cache_cap_mb
            .clamp(limits.min_mb, limits.max_mb);
        if !matches!(s.a11y.text_size.as_str(), "normal" | "large" | "larger") {
            s.a11y.text_size = "normal".into();
        }
        if !matches!(s.appearance.theme.as_str(), "dark" | "light") {
            s.appearance.theme = "dark".into();
        }
        // Route-mode ⇄ legacy `use_tor` reconciliation: migrate a legacy file that
        // set only `use_tor=true` (route_mode defaulted to PreferServer) into
        // TorOnly, then keep `use_tor` synced to route_mode so older readers stay
        // consistent. (`use_tor` can only be true when route_mode is TorOnly after a
        // save, so this migration fires only on genuinely pre-route_mode files.)
        if s.connection.route_mode == RouteMode::PreferServer && s.connection.use_tor {
            s.connection.route_mode = RouteMode::TorOnly;
        }
        s.connection.use_tor = s.connection.route_mode == RouteMode::TorOnly;
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_directory_pub_reads_pinned_key() {
        let tmp = std::env::temp_dir().join(format!("maxsecu-cfg-{}", n()));
        std::fs::create_dir_all(tmp.join("config")).unwrap();
        // Missing → a sanitized "untrusted" error (fail closed; no admin/browse
        // without a pinned root).
        assert_eq!(load_directory_pub(&tmp).unwrap_err().code, "untrusted");
        // Present (exactly 32 bytes) → returned verbatim.
        let key = [0x7Du8; 32];
        std::fs::write(tmp.join("config").join("directory_pub.der"), key).unwrap();
        assert_eq!(load_directory_pub(&tmp).unwrap(), key);
        // Wrong length → fail closed.
        std::fs::write(tmp.join("config").join("directory_pub.der"), [0u8; 31]).unwrap();
        assert_eq!(load_directory_pub(&tmp).unwrap_err().code, "untrusted");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn recovery_recipient_username_reads_config() {
        let tmp = std::env::temp_dir().join(format!("mxcfg-rr-{}", n()));
        std::fs::create_dir_all(tmp.join("config")).unwrap();
        assert_eq!(
            recovery_recipient_username(&tmp).unwrap_err().code,
            "no_recovery_recipient"
        );
        std::fs::write(
            tmp.join("config").join("recovery_recipient.txt"),
            "  recovery-1\n",
        )
        .unwrap();
        assert_eq!(recovery_recipient_username(&tmp).unwrap(), "recovery-1");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn missing_config_defaults_to_manual() {
        let dir = std::env::temp_dir().join(format!("maxsecu-cfg-{}", n()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = ConnectionConfig::load(&dir);
        assert!(!cfg.auto_connect);
        assert_eq!(cfg.server, "");
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = std::env::temp_dir().join(format!("maxsecu-cfg-{}", n()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = ConnectionConfig {
            server: "localhost:8443".into(),
            use_tor: false,
            auto_connect: true,
        };
        cfg.save(&dir).unwrap();
        assert_eq!(ConnectionConfig::load(&dir), cfg);
    }

    #[test]
    fn settings_roundtrip_and_defaults_and_clamp() {
        let dir = std::env::temp_dir().join(format!("mxset-{}", n()));
        std::fs::create_dir_all(&dir).unwrap();
        // Missing → sane defaults.
        let d = SettingsConfig::load(&dir);
        assert!(!d.a11y.reduced_motion && !d.a11y.high_contrast);
        assert_eq!(d.a11y.text_size, "normal");
        assert_eq!(d.performance.ram_cache_cap_mb, 256);
        // Round-trip.
        let mut s = SettingsConfig::default();
        s.a11y.reduced_motion = true;
        s.a11y.text_size = "large".into();
        s.performance.ram_cache_cap_mb = 1024;
        s.save(&dir).unwrap();
        assert_eq!(SettingsConfig::load(&dir), s);
        // Clamp: out-of-range cap and bad text_size are normalized.
        let mut bad = SettingsConfig::default();
        bad.performance.ram_cache_cap_mb = 99_999_999;
        bad.a11y.text_size = "huge".into();
        let limits = crate::ram::compute_ram_limits(crate::ram::system_total_mb_public());
        let norm = bad.normalized();
        assert!(norm.performance.ram_cache_cap_mb <= limits.max_mb);
        assert!(norm.performance.ram_cache_cap_mb >= limits.min_mb);
        assert_eq!(norm.a11y.text_size, "normal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appearance_theme_defaults_dark_and_normalizes() {
        let s = SettingsConfig::default();
        assert_eq!(s.appearance.theme, "dark");
        // An unknown theme normalizes back to dark.
        let mut bad = SettingsConfig::default();
        bad.appearance.theme = "neon".into();
        assert_eq!(bad.normalized().appearance.theme, "dark");
    }

    #[test]
    fn route_mode_defaults_migrates_legacy_use_tor_and_stays_synced() {
        // Default = prefer-server, use_tor false.
        let d = SettingsConfig::default().normalized();
        assert_eq!(d.connection.route_mode, RouteMode::PreferServer);
        assert!(!d.connection.use_tor);

        // A legacy file with only `use_tor: true` (no route_mode) migrates to TorOnly.
        let legacy: SettingsConfig =
            serde_json::from_str(r#"{"connection":{"use_tor":true}}"#).unwrap();
        let m = legacy.normalized();
        assert_eq!(m.connection.route_mode, RouteMode::TorOnly);
        assert!(m.connection.use_tor); // kept synced

        // Explicit route_mode round-trips and drives use_tor.
        let dir = std::env::temp_dir().join(format!("mxroute-{}", n()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = SettingsConfig::default();
        s.connection.route_mode = RouteMode::PreferDropbox;
        s.save(&dir).unwrap();
        let back = SettingsConfig::load(&dir);
        assert_eq!(back.connection.route_mode, RouteMode::PreferDropbox);
        assert!(!back.connection.use_tor); // only TorOnly sets it
        // kebab-case on the wire.
        let json = serde_json::to_string(&s.connection).unwrap();
        assert!(json.contains("prefer-dropbox"), "kebab-case route_mode: {json}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ram_cap_clamps_into_computed_bounds() {
        use crate::ram::compute_ram_limits;
        let limits = compute_ram_limits(16384); // min 64, max 10240
        let mut s = SettingsConfig::default();
        s.performance.ram_cache_cap_mb = 99_999;
        assert_eq!(
            s.normalized_with_ram(&limits).performance.ram_cache_cap_mb,
            10240
        );
        s.performance.ram_cache_cap_mb = 1;
        assert_eq!(
            s.normalized_with_ram(&limits).performance.ram_cache_cap_mb,
            64
        );
    }

    fn n() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
