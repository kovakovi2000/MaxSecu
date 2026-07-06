//! Best-effort free-space probe for the Disk-mode cache gauge denominator (D5a).
//! Probed ONCE at startup and stashed; the gauge divides the on-disk cache size by
//! this. Best-effort: any failure yields `None` and the UI falls back to showing
//! the raw on-disk size without a denominator.

/// Best-effort free bytes on the volume holding `app_dir`, probed ONCE at startup.
/// Returns `None` on any failure (never panics).
pub fn free_bytes_for(app_dir: &std::path::Path) -> Option<u64> {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();
    // Longest mount-point prefix match wins (handles nested mounts).
    disks
        .iter()
        .filter(|d| app_dir.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .map(|d| d.available_space())
}

#[cfg(test)]
mod tests {
    #[test]
    fn free_bytes_never_panics() {
        let _ = super::free_bytes_for(std::path::Path::new("Z:/definitely/not/mounted/here"));
        let some = super::free_bytes_for(&std::env::temp_dir());
        assert!(some.map_or(true, |b| b > 0));
    }
}
