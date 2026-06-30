//! Physical-RAM sizing for the in-memory decrypted-content cache (spec §6.1).
//! The cap defaults to 10% of system RAM, floored at 64 MiB, and is never allowed
//! above (total − 6 GB) so the OS + app keep working room on small machines.

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
/// total − 6 GB); default = clamp(total / 10, min, max).
pub fn compute_ram_limits(total_mb: u64) -> RamLimits {
    let min_mb = MIN_MB;
    let ceiling = total_mb.saturating_sub(HEADROOM_MB) as u32;
    let max_mb = ceiling.max(min_mb);
    let ten_pct = (total_mb / 10) as u32;
    let default_mb = ten_pct.clamp(min_mb, max_mb);
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

/// `ram_limits` — the slider/number bounds + first-run default for the RAM-cache
/// control. Read by the Settings screen + quick-settings so the UI cannot select
/// a cap above (total − 6 GB).
#[tauri::command]
pub async fn ram_limits() -> Result<RamLimits, UiError> {
    Ok(compute_ram_limits(system_total_mb()))
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
        // 8 GiB total → max = 2048; default = 819 (10%).
        let l = compute_ram_limits(8192);
        assert_eq!(l.max_mb, 2048);
        assert_eq!(l.default_mb, 819);
    }
}
