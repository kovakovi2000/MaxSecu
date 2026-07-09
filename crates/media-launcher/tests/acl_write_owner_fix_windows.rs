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
//! This test creates its base dir UNDER the crate manifest dir, which on the dev
//! volume inherits exactly the restrictive `Authenticated Users:(M)` ACL that
//! triggers the bug — so it is a faithful reproduction. It asserts the POSITIVE
//! requirement (a `ReadWrite` grant on a child of a CREATOR-OWNER-granted base
//! succeeds) unconditionally, and additionally documents the negative (the same
//! grant on a child of an UN-granted base is denied) when the runner is not
//! privileged enough to have `WRITE_OWNER` anyway.
#![cfg(windows)]

use std::path::{Path, PathBuf};

use maxsecu_media_launcher::{
    grant_creator_owner_full_control, grant_path_to_appcontainer, GrantAccess,
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
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("target-acltest-{tag}-{}-{nanos}", std::process::id()));
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

/// The fix: under a base that has been granted an inheritable CREATOR OWNER
/// Full-Control ACE, a `ReadWrite` (label-setting) AppContainer grant on a child
/// job dir SUCCEEDS — even on a volume whose inherited ACL is only *Modify*.
#[test]
fn readwrite_grant_succeeds_under_creator_owner_granted_base() {
    let base = ScratchDir::new("fixed");
    grant_creator_owner_full_control(&base.0).expect("grant CREATOR OWNER full control to base");

    // A child created AFTER the base grant inherits an effective Full-Control ACE
    // (incl. WRITE_OWNER) for this process — so the Low-IL label set is permitted.
    let job = base.child("maxsecu-vjob-sim");
    let grant = grant_path_to_appcontainer(&job, GrantAccess::ReadWrite)
        .expect("ReadWrite grant (incl. Low-IL label) must succeed under granted base");
    grant.revoke().expect("revoke restores prior DACL/label");
}

/// Documents the bug the fix addresses: without the base grant, the same
/// `ReadWrite` grant's label set is denied for lack of WRITE_OWNER. Skipped as a
/// hard assertion when the runner happens to have WRITE_OWNER anyway (e.g. an
/// elevated/admin process), since then the reproduction is inconclusive.
#[test]
fn readwrite_grant_without_base_fix_is_denied_or_inconclusive() {
    let base = ScratchDir::new("buggy");
    let job = base.child("maxsecu-vjob-sim");
    match grant_path_to_appcontainer(&job, GrantAccess::ReadWrite) {
        Err(e) => {
            // Expected on a non-privileged runner: the label set is the denied step.
            assert!(
                e.ctx.contains("label") || e.ctx.contains("SetNamedSecurityInfo"),
                "expected the mandatory-label set to be the denied step, got ctx={:?}",
                e.ctx
            );
        }
        Ok(grant) => {
            // Runner had WRITE_OWNER regardless (elevated / permissive volume ACL):
            // reproduction inconclusive, but nothing is wrong. Clean up.
            eprintln!(
                "note: ReadWrite grant succeeded without the base fix — runner appears to \
                 already have WRITE_OWNER (elevated or permissive ACL); bug not reproduced here."
            );
            grant.revoke().expect("revoke");
        }
    }
}
