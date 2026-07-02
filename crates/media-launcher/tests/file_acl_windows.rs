//! `cfg(windows)` integration test for the scoped AppContainer path-ACL grant
//! (Task 2.1, media-sandbox). Verifies that
//! [`grant_path_to_appcontainer`](maxsecu_media_launcher::grant_path_to_appcontainer)
//! genuinely merges an allow ACE for the capability-free AppContainer SID into a
//! path's DACL — observed by reading the DACL back via `GetNamedSecurityInfoW` +
//! `GetExplicitEntriesFromAclW` — and that revoke (explicit and via `Drop`)
//! removes it again, restoring the prior DACL. The `ReadWrite` directory case
//! additionally asserts the Low mandatory integrity label is set and then removed.
//!
//! Windows-only; single-threaded (each case uses a distinct temp path, so the
//! cases are independent, but the launcher's AppContainer profile create/derive is
//! kept serial). `unsafe` is needed for the read-back FFI, so this test target
//! re-allows it (the crate denies `unsafe_code` outside the audited `win32`
//! module).
#![cfg(windows)]
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use maxsecu_media_launcher::{appcontainer_sid_string, grant_path_to_appcontainer, GrantAccess};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetExplicitEntriesFromAclW, GetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    SE_FILE_OBJECT, TRUSTEE_IS_SID,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

fn wide(p: &Path) -> Vec<u16> {
    OsStr::new(p)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Stringify a SID (`S-1-…`), freeing the API buffer. `None` on failure.
unsafe fn sid_string(sid: PSID) -> Option<String> {
    let mut p: windows_sys::core::PWSTR = ptr::null_mut();
    if ConvertSidToStringSidW(sid, &mut p) == 0 {
        return None;
    }
    let mut len = 0isize;
    while *p.offset(len) != 0 {
        len += 1;
    }
    let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len as usize));
    LocalFree(p as _);
    Some(s)
}

/// Read back the explicit `S-1-…` SID strings present in `path`'s DACL.
unsafe fn dacl_sid_strings(path: &Path) -> Vec<String> {
    let wpath = wide(path);
    let mut pdacl: *mut ACL = ptr::null_mut();
    let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let err = GetNamedSecurityInfoW(
        wpath.as_ptr(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut pdacl,
        ptr::null_mut(),
        &mut psd,
    );
    assert_eq!(err, 0, "GetNamedSecurityInfoW(DACL) failed: 0x{err:08X}");
    let mut out = Vec::new();
    if !pdacl.is_null() {
        let mut count: u32 = 0;
        let mut entries: *mut EXPLICIT_ACCESS_W = ptr::null_mut();
        let e2 = GetExplicitEntriesFromAclW(pdacl, &mut count, &mut entries);
        assert_eq!(e2, 0, "GetExplicitEntriesFromAclW failed: 0x{e2:08X}");
        for i in 0..count as isize {
            let ea = &*entries.offset(i);
            if ea.Trustee.TrusteeForm == TRUSTEE_IS_SID {
                if let Some(s) = sid_string(ea.Trustee.ptstrName as PSID) {
                    out.push(s);
                }
            }
        }
        if !entries.is_null() {
            LocalFree(entries as _);
        }
    }
    if !psd.is_null() {
        LocalFree(psd as _);
    }
    out
}

/// Whether `path` carries an explicit mandatory integrity label (a present,
/// non-empty label SACL).
unsafe fn has_integrity_label(path: &Path) -> bool {
    let wpath = wide(path);
    let mut psacl: *mut ACL = ptr::null_mut();
    let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let err = GetNamedSecurityInfoW(
        wpath.as_ptr(),
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut psacl,
        &mut psd,
    );
    assert_eq!(err, 0, "GetNamedSecurityInfoW(LABEL) failed: 0x{err:08X}");
    let present = !psacl.is_null() && (*psacl).AceCount > 0;
    if !psd.is_null() {
        LocalFree(psd as _);
    }
    present
}

/// A unique scratch directory under the system temp dir for one test case.
fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("maxsecu_acl_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create scratch dir");
    d
}

#[test]
fn read_execute_file_grant_then_revoke() {
    let sid = appcontainer_sid_string().expect("derive container SID");
    let dir = scratch("rx");
    let file = dir.join("input.bin");
    std::fs::write(&file, b"attacker-authored bytes").expect("write input");

    let before = unsafe { dacl_sid_strings(&file) };
    assert!(
        !before.contains(&sid),
        "container SID unexpectedly present BEFORE grant: {before:?}"
    );

    let grant = grant_path_to_appcontainer(&file, GrantAccess::ReadExecute).expect("grant");
    let during = unsafe { dacl_sid_strings(&file) };
    assert!(
        during.contains(&sid),
        "container SID ACE missing AFTER grant: {during:?} (expected {sid})"
    );

    grant.revoke().expect("revoke");
    let after = unsafe { dacl_sid_strings(&file) };
    assert!(
        !after.contains(&sid),
        "container SID ACE NOT removed after revoke: {after:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn read_write_dir_grant_label_then_revoke_via_drop() {
    let sid = appcontainer_sid_string().expect("derive container SID");
    let dir = scratch("rw");

    assert!(
        !unsafe { dacl_sid_strings(&dir) }.contains(&sid),
        "container SID unexpectedly present before grant"
    );
    assert!(
        !unsafe { has_integrity_label(&dir) },
        "unexpected pre-existing integrity label on fresh temp dir"
    );

    {
        let _grant = grant_path_to_appcontainer(&dir, GrantAccess::ReadWrite).expect("grant rw");
        let during = unsafe { dacl_sid_strings(&dir) };
        assert!(
            during.contains(&sid),
            "container SID ACE missing after ReadWrite grant: {during:?} (expected {sid})"
        );
        assert!(
            unsafe { has_integrity_label(&dir) },
            "Low integrity label missing after ReadWrite grant"
        );
        // _grant drops here -> revoke via Drop (the RAII safety net).
    }

    let after = unsafe { dacl_sid_strings(&dir) };
    assert!(
        !after.contains(&sid),
        "container SID ACE NOT removed after Drop-revoke: {after:?}"
    );
    assert!(
        !unsafe { has_integrity_label(&dir) },
        "integrity label NOT removed after Drop-revoke"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
