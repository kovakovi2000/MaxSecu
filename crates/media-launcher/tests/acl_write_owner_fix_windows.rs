//! `cfg(windows)` regression test for the in-folder-temp WRITE_OWNER fix.
//!
//! Background: the confined-transcode workspace grant
//! ([`grant_path_to_appcontainer`](maxsecu_media_launcher::grant_path_to_appcontainer)
//! with [`GrantAccess::ReadWrite`]) drops each per-job dir to a **Low mandatory
//! integrity label** via `SetNamedSecurityInfoW(.. LABEL ..)`. Windows only permits
//! setting a mandatory label with **`WRITE_OWNER`** access to the object. When the
//! portable folder lives on a volume whose inherited ACL grants the user merely
//! *Modify* (typical of a non-system data drive — `Authenticated Users:(M)`), a
//! freshly created job dir gives its creator no `WRITE_OWNER`, so the label set is
//! `ACCESS_DENIED` and video ingest fails ("That video could not be processed.").
//!
//! [`grant_creator_owner_full_control`](maxsecu_media_launcher::grant_creator_owner_full_control)
//! fixes this by adding an inheritable CREATOR OWNER Full-Control ACE to the temp
//! root, so each child job dir inherits an effective Full-Control (incl.
//! `WRITE_OWNER`) ACE for its creator — reproducing the ACL `%TEMP%` already carries.
//!
//! The test creates its dirs UNDER the crate manifest dir, which on the dev volume
//! inherits exactly the restrictive `Authenticated Users:(M)` ACL that triggers the
//! bug — a faithful reproduction. It runs the full narrative in ONE sequential body
//! (no intra-file parallelism) and wraps the AppContainer grant calls in a bounded
//! retry, so a transient cross-process contention hiccup (other AppContainer test
//! binaries running concurrently, or Defender scanning the fresh dirs) cannot flake
//! it. The hard assertion is the POSITIVE requirement: under a CREATOR-OWNER-granted
//! base the label-setting `ReadWrite` grant succeeds. The negative (denied without
//! the fix) is observed best-effort and only logged.
#![cfg(windows)]

use std::path::{Path, PathBuf};

use maxsecu_media_launcher::{
    grant_creator_owner_full_control, grant_path_to_appcontainer, GrantAccess, PathGrant,
    SpawnError,
};

/// A unique throwaway dir under the crate manifest dir (on the dev volume, so it
/// inherits the restrictive data-drive ACL). Removed on `Drop`.
struct ScratchDir(PathBuf);
impl ScratchDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "target-acltest-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch base");
        ScratchDir(dir)
    }
    fn child(&self, name: &str) -> PathBuf {
        let c = self.0.join(name);
        std::fs::create_dir_all(&c).expect("create child job dir");
        c
    }
}
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Attempt a ReadWrite AppContainer grant, retrying a few times to absorb transient
/// cross-process contention (concurrent AppContainer test binaries / AV scans).
/// Returns the last result; success short-circuits.
fn grant_rw_with_retry(dir: &Path) -> Result<PathGrant, SpawnError> {
    let mut last: Option<SpawnError> = None;
    for attempt in 0..5 {
        match grant_path_to_appcontainer(dir, GrantAccess::ReadWrite) {
            Ok(g) => return Ok(g),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(60 * (attempt + 1)));
            }
        }
    }
    Err(last.unwrap())
}

/// The fix, end to end: without the base grant a label-setting `ReadWrite` grant is
/// denied for lack of WRITE_OWNER (observed best-effort); after
/// `grant_creator_owner_full_control`, a child job dir inherits WRITE_OWNER and the
/// same grant SUCCEEDS.
#[test]
fn creator_owner_grant_restores_write_owner_for_confined_workspace() {
    // Phase 1 — observe the bug (best-effort; a privileged/elevated runner may have
    // WRITE_OWNER regardless, in which case the reproduction is inconclusive).
    {
        let base = ScratchDir::new("buggy");
        let job = base.child("maxsecu-vjob-sim");
        match grant_path_to_appcontainer(&job, GrantAccess::ReadWrite) {
            Err(e) => assert!(
                e.ctx.contains("SetNamedSecurityInfo") || e.ctx.contains("label"),
                "expected the mandatory-label/DACL set to be the denied step, got ctx={:?}",
                e.ctx
            ),
            Ok(g) => {
                eprintln!(
                    "note: ReadWrite grant succeeded without the base fix — runner appears to \
                     already have WRITE_OWNER (elevated or permissive ACL); bug not reproduced."
                );
                g.revoke().expect("revoke");
            }
        }
    }

    // Phase 2 — the fix: a child created under a CREATOR-OWNER-granted base inherits
    // an effective Full-Control (incl. WRITE_OWNER) ACE, so the Low-IL label set is
    // permitted. This is the hard requirement.
    let base = ScratchDir::new("fixed");
    grant_creator_owner_full_control(&base.0).expect("grant CREATOR OWNER full control to base");
    let job = base.child("maxsecu-vjob-sim");
    let grant = grant_rw_with_retry(&job)
        .expect("ReadWrite grant (incl. Low-IL label) must succeed under a granted base");
    grant.revoke().expect("revoke restores prior DACL/label");
}
