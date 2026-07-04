//! Physical-RAM sizing for the in-memory decrypted-content cache (spec §6.1).
//! The cap defaults to max(10% of system RAM, 1 GiB), floored at 64 MiB, and is
//! never allowed above (total − 6 GB) so the OS + app keep working room on small
//! machines (where the (total − 6 GB) ceiling can pull the default back below 1 GiB).

use serde::Serialize;

use crate::error::UiError;

const MIN_MB: u32 = 64;
const HEADROOM_MB: u64 = 6144; // 6 GiB reserved for the OS + the rest of the app.

/// The slider/number bounds the UI uses for the RAM-cache control, plus the
/// first-run default. All in whole MiB.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct RamLimits {
    pub default_mb: u32,
    pub min_mb: u32,
    pub max_mb: u32,
}

/// Pure RAM-cap math (unit-tested without touching the OS): max = max(min,
/// total − 6 GB); default = clamp(max(total / 10, 1 GiB), min, max).
pub fn compute_ram_limits(total_mb: u64) -> RamLimits {
    let min_mb = MIN_MB;
    let ceiling = total_mb.saturating_sub(HEADROOM_MB) as u32;
    let max_mb = ceiling.max(min_mb);
    // Default to at least 1 GiB (or 10% of RAM if larger), bounded by the ceiling.
    let ten_pct = (total_mb / 10) as u32;
    let default_mb = ten_pct.max(1024).clamp(min_mb, max_mb);
    RamLimits {
        default_mb,
        min_mb,
        max_mb,
    }
}

/// Total physical RAM in whole MiB, via `sysinfo`. Only this function touches
/// the OS; `compute_ram_limits` stays pure for testing.
fn system_total_mb() -> u64 {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_memory();
    // `total_memory()` is BYTES on sysinfo 0.30+. Convert to MiB.
    sys.total_memory() / (1024 * 1024)
}

/// Public shim so `config::SettingsConfig::normalized()` can source the live total
/// without duplicating the sysinfo read. (Tests use `compute_ram_limits` directly.)
pub fn system_total_mb_public() -> u64 {
    system_total_mb()
}

/// `ram_limits` — the slider/number bounds + first-run default for the RAM-cache
/// control. Read by the Settings screen + quick-settings so the UI cannot select
/// a cap above (total − 6 GB).
#[tauri::command]
pub async fn ram_limits() -> Result<RamLimits, UiError> {
    Ok(compute_ram_limits(system_total_mb()))
}

/// Live process + budget memory figures for the RAM-usage gauge in the UI.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct MemoryStats {
    pub used_bytes: Option<u64>,  // process RSS; None if the OS query is unavailable (fail-soft)
    pub budget_bytes: u64,
}

/// Current process resident memory in bytes, or None if unavailable (fail-soft — never panic).
fn current_process_rss_bytes() -> Option<u64> {
    use sysinfo::{get_current_pid, ProcessesToUpdate, System};
    let pid = get_current_pid().ok()?;
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    sys.process(pid).map(|p| p.memory()) // sysinfo 0.33: memory() is RSS in bytes
}

/// `memory_stats` — current process RSS and the RAM budget ceiling, for the
/// quick-settings rainbow gauge. Fail-soft: `used_bytes` is `None` if the OS
/// process query is unavailable on this platform.
#[tauri::command]
pub async fn memory_stats() -> Result<MemoryStats, UiError> {
    let budget_bytes = compute_ram_limits(system_total_mb()).max_mb as u64 * 1024 * 1024;
    Ok(MemoryStats { used_bytes: current_process_rss_bytes(), budget_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_machine_uses_ten_percent_under_a_total_minus_6gb_ceiling() {
        // 16 GiB total → max = 16384-6144 = 10240; default = 1638 (10%).
        let l = compute_ram_limits(16384);
        assert_eq!(l.min_mb, 64);
        assert_eq!(l.max_mb, 10240);
        assert_eq!(l.default_mb, 1638);
    }

    #[test]
    fn small_machine_floors_at_64mb() {
        // 4 GiB total → total-6GB saturates to 0 → max floored to 64; default
        // clamps up to 64.
        let l = compute_ram_limits(4096);
        assert_eq!(l.max_mb, 64);
        assert_eq!(l.default_mb, 64);
    }

    #[test]
    fn mid_machine_ceiling_and_default() {
        // 8 GiB total → max = 2048; default = max(819, 1024) = 1024 (1 GiB floor).
        let l = compute_ram_limits(8192);
        assert_eq!(l.max_mb, 2048);
        assert_eq!(l.default_mb, 1024);
    }
}
