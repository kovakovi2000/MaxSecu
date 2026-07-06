//! ConnectionConfig: where to connect and whether to auto-connect. The test
//! build ships an auto-connect config (spec §4.4); the "later" build leaves
//! `auto_connect=false` and the user types the server on the connect screen.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio_rustls::rustls::{ClientConfig, RootCertStore};

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

/// The offline-pinned trust anchors for the out-of-band **sink** (T4 / spec §0
/// D-OQ1). Held to the SAME trust model as the D5 directory pin above:
/// build-/deploy-time pinned, NEVER server-served — the whole point is that a
/// compromised app operator cannot influence the revocation anchor. Passed to
/// [`crate::sink::fetch_anchored_head`], which returns a head only after a served
/// anchor proof validates against these allowlists.
#[derive(Debug)]
pub struct SinkPins {
    /// The sink's socket address (its OWN endpoint, independent of the app server).
    pub addr: SocketAddr,
    /// The TLS `server_name` presented for the pinned-cert check (split from
    /// `addr` so a loopback test can dial an ephemeral port while validating a
    /// `localhost` SAN — mirrors `HttpSinkClient::new`).
    pub server_name: String,
    /// A client TLS config whose ONLY trust root is the pinned sink cert.
    pub tls: Arc<ClientConfig>,
    /// The pinned custodian public keys for the co-signature anchor-proof form
    /// (`AnchorProof::CustodianCoSig`). Empty ⇒ that form is unvalidatable.
    pub custodian_pubs: Vec<[u8; 32]>,
    /// The pinned transparency-log public keys for the inclusion anchor-proof
    /// form (`AnchorProof::TransparencyInclusion`). Empty ⇒ that form is
    /// unvalidatable (the v1 deployment ships only the custodian form).
    pub transparency_log_pubs: Vec<[u8; 32]>,
}

/// The on-disk pinned sink endpoint (`<dir>/config/sink.json`): where the sink
/// lives + the name its cert must present. The TLS root and the key allowlists
/// are pinned in sibling files (raw DER / raw key bytes), mirroring
/// `directory_pub.der`.
#[derive(Debug, Clone, Deserialize)]
struct SinkEndpointFile {
    addr: String,
    server_name: String,
}

/// Build a client TLS config that trusts ONLY the pinned sink root cert (raw
/// DER). TLS 1.3-only + `aws_lc_rs`, matching the app-server pinned-channel
/// precedent (`transport::pinned_client_config`): restricting to 1.3 avoids a
/// downgrade to a weaker suite against the pinned sink. No public-CA roots are
/// added — the pinned cert is the only accepted sink identity. Exposed for the
/// sink test harness (a loopback sink presents a runtime cert).
pub fn client_config_for_pinned_root(root_der: &[u8]) -> Result<Arc<ClientConfig>, UiError> {
    use tokio_rustls::rustls::pki_types::CertificateDer;
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .map_err(|_| UiError::new("sink_unpinned", "The sink's TLS root is not pinned."))?;
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .map_err(|_| UiError::new("sink_tls", "The pinned sink transport failed to init."))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Read a pinned allowlist file: a raw concatenation of 32-byte public keys
/// (`len % 32 == 0`). A missing file for a NON-required list is an empty
/// allowlist (that anchor-proof form is simply unvalidatable); a missing required
/// list, or any malformed length, fails closed.
fn read_pinned_keys(path: &Path, required: bool) -> Result<Vec<[u8; 32]>, UiError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) if !required => return Ok(Vec::new()),
        Err(_) => {
            return Err(UiError::new(
                "sink_unpinned",
                "The sink allowlist is not pinned.",
            ))
        }
    };
    if bytes.is_empty() {
        return if required {
            Err(UiError::new(
                "sink_unpinned",
                "The pinned sink allowlist is empty.",
            ))
        } else {
            Ok(Vec::new())
        };
    }
    if bytes.len() % 32 != 0 {
        return Err(UiError::new(
            "sink_unpinned",
            "The pinned sink allowlist is malformed.",
        ));
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|c| {
            let mut k = [0u8; 32];
            k.copy_from_slice(c);
            k
        })
        .collect())
}

/// Load the pinned [`SinkPins`] from `<dir>/config/`:
/// * `sink.json` — `{ "addr": "host:port", "server_name": "…" }`;
/// * `sink_root.der` — the sink's pinned TLS root cert (raw DER);
/// * `sink_custodians.der` — raw 32-byte custodian keys (REQUIRED, ≥1);
/// * `sink_transparency.der` — raw 32-byte log keys (OPTIONAL; absent ⇒ empty).
///
/// Any absent/malformed pin fails closed with a sanitized `sink_unpinned` error —
/// there is no reshare-revocation anchor without a pinned sink (no server-served
/// fallback, by design).
pub fn load_sink_pins(dir: &Path) -> Result<SinkPins, UiError> {
    let cfg = dir.join("config");
    let raw = std::fs::read(cfg.join("sink.json"))
        .map_err(|_| UiError::new("sink_unpinned", "The sink endpoint is not pinned."))?;
    let ep: SinkEndpointFile = serde_json::from_slice(&raw)
        .map_err(|_| UiError::new("sink_unpinned", "The pinned sink endpoint is malformed."))?;
    let addr: SocketAddr = ep
        .addr
        .parse()
        .map_err(|_| UiError::new("sink_unpinned", "The pinned sink address is malformed."))?;
    let server_name = ep.server_name.trim().to_owned();
    if server_name.is_empty() {
        return Err(UiError::new(
            "sink_unpinned",
            "The pinned sink server name is empty.",
        ));
    }
    let root = std::fs::read(cfg.join("sink_root.der"))
        .map_err(|_| UiError::new("sink_unpinned", "The sink's TLS root is not pinned."))?;
    let tls = client_config_for_pinned_root(&root)?;
    let custodian_pubs = read_pinned_keys(&cfg.join("sink_custodians.der"), true)?;
    let transparency_log_pubs = read_pinned_keys(&cfg.join("sink_transparency.der"), false)?;
    Ok(SinkPins {
        addr,
        server_name,
        tls,
        custodian_pubs,
        transparency_log_pubs,
    })
}

/// Load the offline-pinned **directory key-transparency (KT) log** public keys
/// from `<dir>/config/kt_log.der` (a raw concatenation of 32-byte Ed25519 keys) —
/// held to the SAME build-/deploy-time pinned trust model as the D5 directory pin
/// and the sink pins, NEVER server-served (the whole point of KT is that a
/// compromised operator cannot influence which key signs the checkpoint the client
/// trusts). These are the keys a KT checkpoint signature must verify under
/// ([`crate::transparency::verify_binding_transparency`]); a checkpoint not signed
/// by a pinned key is equivocation and fails closed.
///
/// Absent ⇒ an EMPTY allowlist: the KT gate is OPT-IN (mirroring the optional
/// `sink_transparency.der` list), so a deployment that has not pinned a KT key runs
/// today's D5-only browse/open verification rather than failing every open closed.
/// A malformed (non-multiple-of-32) file still fails closed.
pub fn load_kt_log_pubs(dir: &Path) -> Result<Vec<[u8; 32]>, UiError> {
    // Absent ⇒ Ok(empty) (opt-in, not required). A malformed file fails closed with
    // a KT-specific code (not the sink's `sink_unpinned` misnomer).
    read_pinned_keys(&dir.join("config").join("kt_log.der"), false).map_err(|_| {
        UiError::new(
            "kt_log_unpinned",
            "The pinned key-transparency log key is malformed.",
        )
    })
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

/// Where the ciphertext caches live. `Memory` (default) = an in-process
/// ciphertext LRU that never touches disk (same byte budget) — the ciphertext-in-RAM
/// model. `Disk` = the opt-in ciphertext-on-disk mode (`<dir>/cache/frag/*.frag`).
/// Both store ONLY ciphertext, and both caches (Media + Thumbnails) share this one
/// location toggle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum FragmentCacheLocation {
    Disk,
    #[default]
    Memory,
}

/// The wire form of [`PerformanceSettings`]: reads BOTH the current keys and the
/// legacy `ram_cache_cap_mb`, folding the legacy value into `media_cache_cap_mb`.
/// A direct `serde_json::from_str::<PerformanceSettings>` routes through this via
/// `#[serde(from = "PerformanceSettingsWire")]`, so the migration runs even when a
/// caller bypasses `SettingsConfig::load`/`normalized`. The real struct carries NO
/// `ram_cache_cap_mb` field, so the legacy key never re-serializes on save.
#[derive(Deserialize)]
struct PerformanceSettingsWire {
    #[serde(default)]
    media_cache_cap_mb: u32, // 0 when absent → migrate/default
    #[serde(default)]
    thumb_cache_cap_mb: u32, // 0 when absent → 256
    #[serde(default = "default_feed_concurrency")]
    feed_concurrency: u8,
    #[serde(default = "default_cpu_threads")]
    transcode_threads: u16,
    #[serde(default = "default_cpu_threads")]
    decode_threads: u16,
    #[serde(default)]
    cache_location: FragmentCacheLocation,
    #[serde(default)]
    ram_cache_cap_mb: Option<u32>, // legacy key, read-only
}
impl From<PerformanceSettingsWire> for PerformanceSettings {
    fn from(w: PerformanceSettingsWire) -> Self {
        let media_cache_cap_mb = if w.media_cache_cap_mb == 0 {
            w.ram_cache_cap_mb.filter(|v| *v > 0).unwrap_or(default_media_cap())
        } else {
            w.media_cache_cap_mb
        };
        let thumb_cache_cap_mb = if w.thumb_cache_cap_mb == 0 {
            default_thumb_cap()
        } else {
            w.thumb_cache_cap_mb
        };
        Self {
            media_cache_cap_mb,
            thumb_cache_cap_mb,
            feed_concurrency: w.feed_concurrency,
            transcode_threads: w.transcode_threads,
            decode_threads: w.decode_threads,
            cache_location: w.cache_location,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(from = "PerformanceSettingsWire")]
pub struct PerformanceSettings {
    /// Byte budget (MiB) for the Media cache (video fragments + full-content).
    /// Default 1024. Clamped into the live RAM bounds by `normalized_with_ram`.
    pub media_cache_cap_mb: u32,
    /// Byte budget (MiB) for the Thumbnails cache (card metadata). Default 256.
    /// Clamped into the same RAM bounds (independent value).
    pub thumb_cache_cap_mb: u32,
    /// Feed cards fetched/decoded in parallel. Default 4; clamped 1..=8.
    pub feed_concurrency: u8,
    /// Worker-thread budget for the confined author-side transcode. Default =
    /// available parallelism (logical CPUs); clamped 1..=available.
    pub transcode_threads: u16,
    /// Worker-thread budget for the confined decode path. Default =
    /// available parallelism (logical CPUs); clamped 1..=available.
    ///
    /// NOTE (Task 7.3): video playback now uses the native `<video>` element
    /// (WebView2's own decoder), and the confined decode worker (`media-worker`,
    /// `SubprocessDecoder`/`AppContainerDecoder`) was RETIRED for viewing — see
    /// `media-launcher`'s crate docs. There is therefore currently **no runtime
    /// consumer** for this budget. It stays a surfaced, normalized setting reserved
    /// for when a confined decode path returns (e.g. a preview/thumbnail decode) or
    /// for parallel per-chunk work; wiring it would pass it as a launch ARG to that
    /// worker (never an env var), consistent with the ffmpeg `-threads` path.
    pub decode_threads: u16,
    /// Shared cache-backend location (Media + Thumbnails). Default is `Memory`
    /// (ciphertext-in-RAM); `Disk` is the opt-in ciphertext-on-disk mode.
    pub cache_location: FragmentCacheLocation,
}
impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            media_cache_cap_mb: default_media_cap(),
            thumb_cache_cap_mb: default_thumb_cap(),
            feed_concurrency: default_feed_concurrency(),
            transcode_threads: default_cpu_threads(),
            decode_threads: default_cpu_threads(),
            cache_location: FragmentCacheLocation::default(),
        }
    }
}
fn default_media_cap() -> u32 {
    1024
}
fn default_thumb_cap() -> u32 {
    256
}
fn default_feed_concurrency() -> u8 {
    4
}
/// Available parallelism (logical CPUs, includes SMT/hyperthreads), fallback 1.
/// Saturating cast: a >u16::MAX logical-CPU count clamps to u16::MAX rather than
/// truncating (a truncated 0 would make `normalized_with_ram`'s `clamp(1, 0)` panic).
fn default_cpu_threads() -> u16 {
    std::thread::available_parallelism()
        .map(|n| n.get().min(u16::MAX as usize) as u16)
        .unwrap_or(1)
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
        s.performance.media_cache_cap_mb = s
            .performance
            .media_cache_cap_mb
            .clamp(limits.min_mb, limits.max_mb);
        s.performance.thumb_cache_cap_mb = s
            .performance
            .thumb_cache_cap_mb
            .clamp(limits.min_mb, limits.max_mb);
        let cores = default_cpu_threads();
        s.performance.feed_concurrency = s.performance.feed_concurrency.clamp(1, 8);
        s.performance.transcode_threads = s.performance.transcode_threads.clamp(1, cores);
        s.performance.decode_threads = s.performance.decode_threads.clamp(1, cores);
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
        assert_eq!(d.performance.media_cache_cap_mb, 1024);
        // Round-trip.
        let mut s = SettingsConfig::default();
        s.a11y.reduced_motion = true;
        s.a11y.text_size = "large".into();
        s.performance.media_cache_cap_mb = 1024;
        s.save(&dir).unwrap();
        assert_eq!(SettingsConfig::load(&dir), s);
        // Clamp: out-of-range cap and bad text_size are normalized.
        let mut bad = SettingsConfig::default();
        bad.performance.media_cache_cap_mb = 99_999_999;
        bad.a11y.text_size = "huge".into();
        let limits = crate::ram::compute_ram_limits(crate::ram::system_total_mb_public());
        let norm = bad.normalized();
        assert!(norm.performance.media_cache_cap_mb <= limits.max_mb);
        assert!(norm.performance.media_cache_cap_mb >= limits.min_mb);
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
        s.performance.media_cache_cap_mb = 99_999;
        assert_eq!(
            s.normalized_with_ram(&limits).performance.media_cache_cap_mb,
            10240
        );
        s.performance.media_cache_cap_mb = 1;
        assert_eq!(
            s.normalized_with_ram(&limits).performance.media_cache_cap_mb,
            64
        );
    }

    #[test]
    fn load_sink_pins_reads_pins_and_fails_closed() {
        let dir = std::env::temp_dir().join(format!("mxsink-{}", n()));
        let cfg = dir.join("config");
        std::fs::create_dir_all(&cfg).unwrap();

        // Nothing pinned yet → fail closed (no server-served fallback).
        assert_eq!(load_sink_pins(&dir).unwrap_err().code, "sink_unpinned");

        // Pin the endpoint + a runtime self-signed root + one custodian key.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        std::fs::write(cfg.join("sink_root.der"), cert.cert.der()).unwrap();
        std::fs::write(
            cfg.join("sink.json"),
            br#"{"addr":"127.0.0.1:9443","server_name":"localhost"}"#,
        )
        .unwrap();
        let cust = [0x11u8; 32];
        std::fs::write(cfg.join("sink_custodians.der"), cust).unwrap();

        let pins = load_sink_pins(&dir).unwrap();
        assert_eq!(pins.addr, "127.0.0.1:9443".parse().unwrap());
        assert_eq!(pins.server_name, "localhost");
        assert_eq!(pins.custodian_pubs, vec![cust]);
        // Transparency file absent → empty allowlist (that form unvalidatable).
        assert!(pins.transparency_log_pubs.is_empty());

        // A malformed custodian allowlist (not a multiple of 32) fails closed.
        std::fs::write(cfg.join("sink_custodians.der"), [0u8; 31]).unwrap();
        assert_eq!(load_sink_pins(&dir).unwrap_err().code, "sink_unpinned");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn performance_thread_settings_default_and_clamp() {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get() as u16)
            .unwrap_or(1);
        let d = PerformanceSettings::default();
        assert_eq!(d.feed_concurrency, 4);
        assert_eq!(d.transcode_threads, cores);
        assert_eq!(d.decode_threads, cores);
        // Clamp: feed_concurrency 1..=8; threads 1..=cores.
        let mut bad = SettingsConfig::default();
        bad.performance.feed_concurrency = 99;
        bad.performance.transcode_threads = 9999;
        bad.performance.decode_threads = 0;
        let limits = crate::ram::compute_ram_limits(crate::ram::system_total_mb_public());
        let nrm = bad.normalized_with_ram(&limits).performance;
        assert_eq!(nrm.feed_concurrency, 8);
        assert_eq!(nrm.transcode_threads, cores);
        assert_eq!(nrm.decode_threads, 1);
    }

    #[test]
    fn cache_location_defaults_to_memory_and_back_compat_loads() {
        assert_eq!(
            PerformanceSettings::default().cache_location,
            FragmentCacheLocation::Memory
        );
        // A legacy file (only `ram_cache_cap_mb`, no `cache_location`) → default Memory,
        // and the legacy cap migrates into `media_cache_cap_mb`.
        let json = r#"{"ram_cache_cap_mb":512}"#;
        let p: PerformanceSettings = serde_json::from_str(json).unwrap();
        assert_eq!(p.cache_location, FragmentCacheLocation::Memory);
        assert_eq!(p.media_cache_cap_mb, 512);
    }

    #[test]
    fn migrates_legacy_ram_cache_cap_into_media() {
        // Old settings.json with only ram_cache_cap_mb populates media_cache_cap_mb.
        let json = r#"{"media_cache_cap_mb":0,"thumb_cache_cap_mb":0,"ram_cache_cap_mb":512}"#;
        let p: PerformanceSettings = serde_json::from_str(json).unwrap();
        assert_eq!(p.media_cache_cap_mb, 512);
        assert_eq!(p.thumb_cache_cap_mb, 256); // default when absent/zero
    }

    #[test]
    fn legacy_ram_cache_cap_never_reserializes() {
        // The headline guarantee: reading a legacy blob migrates the value, but the
        // dead legacy key is gone from the model, so a save can never write it back.
        let p: PerformanceSettings =
            serde_json::from_str(r#"{"ram_cache_cap_mb":512}"#).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("ram_cache_cap_mb"), "legacy key re-serialized: {json}");
        assert!(json.contains("media_cache_cap_mb"), "missing media cap: {json}");
    }

    #[test]
    fn both_caps_clamp_to_ram_bounds() {
        let limits = crate::ram::RamLimits {
            default_mb: 1024,
            min_mb: 64,
            max_mb: 2048,
        };
        let mut s = SettingsConfig::default();
        s.performance.media_cache_cap_mb = 99_999;
        s.performance.thumb_cache_cap_mb = 1;
        let n = s.normalized_with_ram(&limits).performance;
        assert!(n.media_cache_cap_mb <= 2048 && n.media_cache_cap_mb >= 64);
        assert!(n.thumb_cache_cap_mb <= 2048 && n.thumb_cache_cap_mb >= 64);
    }

    fn n() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
