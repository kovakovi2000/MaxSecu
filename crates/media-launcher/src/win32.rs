//! Windows **AppContainer + Job Object** confinement for the decode worker
//! (DESIGN §8.1/D30, media-sandbox §2) — the OS isolation that makes a decoder
//! 0-day non-exfiltrating.
//!
//! This is the **only** module in the workspace that uses `unsafe`: raw Win32 FFI
//! via `windows-sys` (OS-API bindings, not a vendored C library). It launches the
//! `media-worker` binary in:
//! * an **AppContainer** with **no capabilities** — no `internetClient`, so the
//!   process **cannot reach the network by capability** (not just firewall), and
//!   a low-privilege token that cannot read the user's files / key blob; and
//! * a **Job Object** with `ACTIVE_PROCESS = 1` (no child processes — can't shell
//!   out), `KILL_ON_JOB_CLOSE`, and a hard **process memory cap** (a
//!   decompression bomb is killed, not hung).
//!
//! Pipe I/O uses `std::fs::File` over the parent handle ends, so only the spawn
//! itself is FFI. The worker output is still validated (`validate_decoded`) — OS
//! isolation does not make the bytes trusted.
#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    FreeSid, GetSecurityDescriptorSacl, ACL, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};

/// A launch/confinement failure: which Win32 step failed + its `GetLastError`/
/// `HRESULT`. Carries no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnError {
    pub ctx: &'static str,
    pub code: u32,
}

impl SpawnError {
    fn last(ctx: &'static str) -> Self {
        // SAFETY: GetLastError is always callable and has no preconditions.
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        SpawnError { ctx, code }
    }
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "win32 {} failed (code 0x{:08X})", self.ctx, self.code)
    }
}

impl std::error::Error for SpawnError {}

/// The result of a confined run: the worker's exit code and the bytes it wrote on
/// stdout.
pub struct ConfinedOutput {
    pub exit_code: u32,
    pub stdout: Vec<u8>,
}

/// The result of a confined **arbitrary-exe** run ([`spawn_confined_exe`], Task
/// 2.2): the program's exit code and a BOUNDED tail of its stderr (diagnostics
/// only — its media goes to a granted output file, never to stdio). `stderr_tail`
/// is capped at [`FFMPEG_STDERR_CAP_BYTES`] (head-kept), so a hostile/verbose
/// program cannot OOM the trusted parent through its error stream.
pub struct ConfinedExeOutput {
    pub exit_code: u32,
    pub stderr_tail: Vec<u8>,
}

/// The AppContainer moniker (stable, app-specific). No capabilities are ever
/// granted to it.
const APPCONTAINER_NAME: &str = "MaxSecu.MediaDecodeWorker.v1";

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)` — the profile is already registered.
const HR_ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;

/// Create-or-derive the capability-free AppContainer SID. Caller must keep the
/// returned SID alive for the lifetime of the spawn (it is referenced by the
/// `SECURITY_CAPABILITIES`).
fn appcontainer_sid() -> Result<PSID, SpawnError> {
    let name = wide(APPCONTAINER_NAME);
    let disp = wide("MaxSecu media decode worker");
    let desc = wide("Network-less, key-less media decode sandbox");
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: all pointers are valid for the call; capabilities are null/0 (no
    // capabilities — the whole point). `sid` receives an owned SID on success.
    let hr = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            disp.as_ptr(),
            desc.as_ptr(),
            ptr::null(),
            0,
            &mut sid,
        )
    };
    if hr == 0 {
        return Ok(sid);
    }
    if hr == HR_ALREADY_EXISTS {
        // SAFETY: deriving the SID for an existing profile; `sid` receives it.
        let hr2 = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
        if hr2 == 0 {
            return Ok(sid);
        }
        return Err(SpawnError {
            ctx: "DeriveAppContainerSid",
            code: hr2 as u32,
        });
    }
    Err(SpawnError {
        ctx: "CreateAppContainerProfile",
        code: hr as u32,
    })
}

/// Format a SID as its `S-1-…` string (for an SDDL ACE). Frees the API buffer.
fn sid_to_string(sid: PSID) -> Result<String, SpawnError> {
    let mut pstr: windows_sys::core::PWSTR = ptr::null_mut();
    // SAFETY: `sid` is a valid SID; `pstr` receives a LocalAlloc'd wide string.
    if unsafe { ConvertSidToStringSidW(sid, &mut pstr) } == 0 {
        return Err(SpawnError::last("ConvertSidToStringSid"));
    }
    let mut len = 0isize;
    // SAFETY: `pstr` is a valid null-terminated wide string.
    unsafe {
        while *pstr.offset(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(pstr, len as usize) };
    let s = String::from_utf16_lossy(slice);
    unsafe { LocalFree(pstr as _) };
    Ok(s)
}

/// Build a security descriptor that grants the pipe to **this AppContainer's SID**
/// and Everyone (`WD`) — without it the AppContainer worker (outside `Everyone`,
/// and not covered by the `AC` alias on this OS) is denied read/write on the
/// anonymous pipe (`ACCESS_DENIED`) and its stdio is silently dropped. Returned
/// descriptor must be freed with [`LocalFree`].
fn appcontainer_pipe_security(sid: PSID) -> Result<*mut core::ffi::c_void, SpawnError> {
    let sidstr = sid_to_string(sid)?;
    // (A;;GA;;;<container sid>) GenericAll to the worker's AppContainer;
    // (A;;GA;;;WD) GenericAll to Everyone (the medium-IL parent).
    let sddl = wide(&format!("D:(A;;GA;;;WD)(A;;GA;;;{sidstr})"));
    let mut psd: *mut core::ffi::c_void = ptr::null_mut();
    // SAFETY: `sddl` is a valid null-terminated wide string; `psd` receives an
    // owned descriptor (LocalAlloc'd) on success.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut psd, ptr::null_mut())
    };
    if ok == 0 {
        return Err(SpawnError::last("ConvertStringSecurityDescriptor"));
    }
    Ok(psd)
}

// ---------------------------------------------------------------------------
// Scoped per-path ACL grant for a confined spawn (Task 2.1, media-sandbox).
//
// A capability-free, Low-IL AppContainer can only open a filesystem path if (a)
// the path's DACL grants the container SID, and (b) for *write*, the object's
// mandatory integrity label permits it (a default Medium-IL object blocks a
// Low-IL subject's write-up). [`grant_path_to_appcontainer`] MERGES one allow ACE
// for the container SID into the path's *existing* DACL (never clobbering it) and,
// for the writable workspace case, drops the object to a Low integrity label so
// the confined worker (Task 2.2's `ffmpeg.exe`) can read its copied-in input and
// write its output while staying network-less / key-less / child-less. The
// returned [`PathGrant`] is an RAII guard that restores the prior DACL (and the
// prior label) on `Drop` — mirroring [`JobGuard`] — so an unwind mid-job cannot
// leave a lingering grant on the user's filesystem.
// ---------------------------------------------------------------------------

/// Access to grant the confined AppContainer worker over a single path for one
/// job. `ReadExecute` is for an input source the worker only reads (e.g. a
/// copied-in media file); `ReadWrite` is for the per-job output workspace the
/// confined transcoder reads from and writes into (and is additionally given a
/// Low integrity label so the Low-IL worker can write to it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAccess {
    /// Read + execute (traverse). For a read-only input.
    ReadExecute,
    /// Read + write. For the writable output workspace; also gets a Low label.
    ReadWrite,
}

impl GrantAccess {
    /// The access-rights mask merged into the path's DACL for the container SID.
    /// Generic rights (as used by the pipe descriptor's `GA`) — the OS maps them
    /// to the file/directory-specific set at access-check time.
    fn rights(self) -> u32 {
        match self {
            GrantAccess::ReadExecute => GENERIC_READ | GENERIC_EXECUTE,
            GrantAccess::ReadWrite => GENERIC_READ | GENERIC_WRITE,
        }
    }

    /// `ReadWrite` additionally needs a Low mandatory label so the Low-IL
    /// AppContainer is not blocked writing up to a default Medium-IL object.
    fn needs_low_label(self) -> bool {
        matches!(self, GrantAccess::ReadWrite)
    }
}

/// SDDL for a **Low** mandatory integrity label (`LW`) with the standard
/// no-write-up policy (`NW`). Applied to a `ReadWrite` workspace so a Low-IL
/// AppContainer subject can write to it (equal-level write is permitted; only
/// subjects *below* Low are blocked).
const LOW_LABEL_SDDL: &str = "S:(ML;;NW;;;LW)";

/// RAII guard for a [`grant_path_to_appcontainer`] grant. On [`revoke`](Self::revoke)
/// or `Drop` it restores the path's prior DACL (removing the merged container ACE)
/// and, if it set one, the prior integrity label — best-effort, so a panicking job
/// driver cannot leave the grant behind. Holds the captured prior security
/// descriptor (which backs `prior_dacl`/`prior_sacl`) until it is freed.
pub struct PathGrant {
    /// The granted path, wide + NUL-terminated (for the restore call).
    path: Vec<u16>,
    /// Owned descriptor captured at grant time; backs `prior_dacl`/`prior_sacl`.
    prior_sd: PSECURITY_DESCRIPTOR,
    /// The path's DACL before the grant (may be null = no prior DACL).
    prior_dacl: *mut ACL,
    /// The path's label SACL before the grant (may be null = no prior label).
    prior_sacl: *mut ACL,
    /// Whether this grant applied a Low label that revoke must undo.
    set_label: bool,
    /// Set once the prior state has been restored, so `Drop` after an explicit
    /// `revoke` is a no-op (no double-restore).
    revoked: bool,
}

impl PathGrant {
    /// Explicitly restore the path's prior DACL/label and free the captured
    /// descriptor. `Drop` is the safety net; this returns the restore result for
    /// callers that want to observe a restore failure.
    pub fn revoke(mut self) -> Result<(), SpawnError> {
        let r = self.do_revoke();
        self.free();
        r
    }

    /// Restore the prior DACL (and prior label, if we set one). Idempotent.
    fn do_revoke(&mut self) -> Result<(), SpawnError> {
        if self.revoked {
            return Ok(());
        }
        self.revoked = true;
        // Remove our merged ACE by re-applying exactly the captured prior DACL.
        let dacl_res = restore_dacl(&self.path, self.prior_dacl);
        // Then restore the prior integrity label, if this grant changed it.
        let label_res = if self.set_label {
            restore_label(&self.path, self.prior_sacl)
        } else {
            Ok(())
        };
        dacl_res.and(label_res)
    }

    /// Free the captured prior descriptor (after `do_revoke` has consumed the
    /// `prior_dacl`/`prior_sacl` pointers that point into it). Idempotent.
    fn free(&mut self) {
        if !self.prior_sd.is_null() {
            // SAFETY: `prior_sd` was LocalAlloc'd by GetNamedSecurityInfoW and is
            // freed exactly once (the pointers into it are no longer used).
            unsafe { LocalFree(self.prior_sd as _) };
            self.prior_sd = ptr::null_mut();
            self.prior_dacl = ptr::null_mut();
            self.prior_sacl = ptr::null_mut();
        }
    }
}

impl Drop for PathGrant {
    fn drop(&mut self) {
        // Safety net: if the caller did not `revoke`, restore the prior state now
        // so an unwind mid-job cannot leave the grant on the user's filesystem.
        let _ = self.do_revoke();
        self.free();
    }
}

/// Free a SID returned by [`appcontainer_sid`]. Both `CreateAppContainerProfile`
/// and `DeriveAppContainerSidFromAppContainerName` return an owned SID that must
/// be released with [`FreeSid`].
fn free_sid(sid: PSID) {
    if !sid.is_null() {
        // SAFETY: `sid` was produced by the AppContainer SID APIs above and is
        // freed exactly once here.
        unsafe { FreeSid(sid) };
    }
}

/// RAII owner of an [`appcontainer_sid`] SID, freeing it on `Drop`. The SID must
/// outlive every step that references it — the `SECURITY_CAPABILITIES` consumed by
/// `CreateProcessW` borrow it — so [`setup_confined_exe_child`] keeps this guard
/// alive across the whole spawn and frees the SID on EVERY exit path (success or
/// any early-error return), unlike the older [`setup_confined_child`] which leaves
/// the SID's lifetime to the process. Declared first in that function so it drops
/// LAST (after `caps` / the attribute list are done with it).
struct SidGuard(PSID);

impl Drop for SidGuard {
    fn drop(&mut self) {
        free_sid(self.0);
    }
}

/// Re-apply exactly `prior_dacl` to `wpath`'s DACL (a null `prior_dacl` reverts to
/// the "no DACL" state the path had before the grant). Writes only DACL info.
fn restore_dacl(wpath: &[u16], prior_dacl: *const ACL) -> Result<(), SpawnError> {
    // SAFETY: `wpath` is a valid NUL-terminated wide path; `prior_dacl` is the
    // captured prior DACL (or null); only DACL info is written.
    let err = unsafe {
        SetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            prior_dacl,
            ptr::null(),
        )
    };
    if err == 0 {
        Ok(())
    } else {
        Err(SpawnError {
            ctx: "SetNamedSecurityInfo.restore_dacl",
            code: err,
        })
    }
}

/// Restore the prior integrity label after a `ReadWrite` grant: re-apply the
/// captured `prior_sacl` (or, if the object had no prior label, apply a NULL label
/// SACL, which drops the Low label this grant added and reverts the object to its
/// implicit Medium integrity). Writes only LABEL info.
fn restore_label(wpath: &[u16], prior_sacl: *const ACL) -> Result<(), SpawnError> {
    // SAFETY: `wpath` is valid; `prior_sacl` is the captured prior label SACL or
    // null (null with LABEL info removes the explicit mandatory label).
    let err = unsafe {
        SetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            prior_sacl,
        )
    };
    if err == 0 {
        Ok(())
    } else {
        Err(SpawnError {
            ctx: "SetNamedSecurityInfo.restore_label",
            code: err,
        })
    }
}

/// Apply the Low mandatory integrity label ([`LOW_LABEL_SDDL`]) to `wpath` so a
/// Low-IL AppContainer can write to it. Reuses the SDDL→descriptor API, extracts
/// the label SACL, and writes it via `LABEL_SECURITY_INFORMATION`.
fn set_low_label(wpath: &[u16]) -> Result<(), SpawnError> {
    let sddl = wide(LOW_LABEL_SDDL);
    let mut psd: *mut core::ffi::c_void = ptr::null_mut();
    // SAFETY: `sddl` is a valid NUL-terminated wide string; `psd` receives an
    // owned (LocalAlloc'd) descriptor on success.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut psd,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(SpawnError::last("ConvertStringSecurityDescriptor.label"));
    }
    let mut present: windows_sys::core::BOOL = 0;
    let mut sacl: *mut ACL = ptr::null_mut();
    let mut defaulted: windows_sys::core::BOOL = 0;
    // SAFETY: `psd` is the descriptor just built; the out-params are valid and the
    // returned `sacl` points into `psd` (alive across the Set call below).
    let got = unsafe { GetSecurityDescriptorSacl(psd, &mut present, &mut sacl, &mut defaulted) };
    if got == 0 || present == 0 || sacl.is_null() {
        // SAFETY: `psd` is the descriptor we just allocated; freed exactly once.
        unsafe { LocalFree(psd) };
        return Err(SpawnError::last("GetSecurityDescriptorSacl.label"));
    }
    // SAFETY: write only the label (SACL); `sacl` points into `psd`, alive here.
    let err = unsafe {
        SetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            sacl,
        )
    };
    // SAFETY: `psd` is freed exactly once after the label has been applied.
    unsafe { LocalFree(psd) };
    if err != 0 {
        return Err(SpawnError {
            ctx: "SetNamedSecurityInfo.label",
            code: err,
        });
    }
    Ok(())
}

/// Grant the capability-free AppContainer worker `access` to `path` (a file or a
/// directory) for the lifetime of the returned [`PathGrant`]. The grant MERGES one
/// allow ACE for the container SID into the path's existing DACL (preserving every
/// existing ACE) and, for [`GrantAccess::ReadWrite`], also drops the object to a
/// Low integrity label. A directory grant is made inheritable
/// (`SUB_CONTAINERS_AND_OBJECTS_INHERIT`) so files the worker creates inside the
/// workspace inherit the container's access. Dropping (or [`revoke`](PathGrant::revoke))
/// the guard restores the path's prior DACL and label.
pub fn grant_path_to_appcontainer(
    path: &Path,
    access: GrantAccess,
) -> Result<PathGrant, SpawnError> {
    let wpath = wide(&path.to_string_lossy());
    let sid = appcontainer_sid()?;

    // Capture the path's CURRENT DACL and label so revoke restores it exactly —
    // we MERGE into the DACL, we never replace it.
    let mut prior_dacl: *mut ACL = ptr::null_mut();
    let mut prior_sacl: *mut ACL = ptr::null_mut();
    let mut prior_sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wpath` is a valid wide path; the out-params are valid; on success
    // `prior_sd` owns a LocalAlloc'd descriptor backing `prior_dacl`/`prior_sacl`.
    let err = unsafe {
        GetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut prior_dacl,
            &mut prior_sacl,
            &mut prior_sd,
        )
    };
    if err != 0 {
        free_sid(sid);
        return Err(SpawnError {
            ctx: "GetNamedSecurityInfo",
            code: err,
        });
    }

    // Build ONE allow ACE for the container SID, then MERGE it into the prior DACL
    // (SetEntriesInAclW copies the existing ACEs into a fresh ACL — non-clobbering).
    let mut trustee: TRUSTEE_W = unsafe { core::mem::zeroed() };
    trustee.pMultipleTrustee = ptr::null_mut();
    trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    trustee.TrusteeForm = TRUSTEE_IS_SID;
    trustee.TrusteeType = TRUSTEE_IS_USER;
    // For TRUSTEE_IS_SID, `ptstrName` carries the SID pointer (cast to PWSTR).
    trustee.ptstrName = sid as windows_sys::core::PWSTR;

    let mut ea: EXPLICIT_ACCESS_W = unsafe { core::mem::zeroed() };
    ea.grfAccessPermissions = access.rights();
    ea.grfAccessMode = GRANT_ACCESS;
    // A directory grant is inheritable so files the worker creates in the
    // workspace inherit the container's access (Task 2.2 writes outputs there); a
    // single-file grant carries no inheritance.
    ea.grfInheritance = if path.is_dir() {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
    ea.Trustee = trustee;

    let mut new_dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `ea` is fully initialized; `prior_dacl` is the captured DACL (may be
    // null); `new_dacl` receives a LocalAlloc'd merged ACL on success.
    let err = unsafe { SetEntriesInAclW(1, &ea, prior_dacl, &mut new_dacl) };
    if err != 0 {
        // SAFETY: `prior_sd` is the captured descriptor; freed once. No DACL was
        // changed, so there is nothing to roll back.
        unsafe { LocalFree(prior_sd as _) };
        free_sid(sid);
        return Err(SpawnError {
            ctx: "SetEntriesInAcl",
            code: err,
        });
    }

    // Apply the merged DACL to the path.
    // SAFETY: `new_dacl` is the merged ACL; only DACL info is written.
    let err = unsafe {
        SetNamedSecurityInfoW(
            wpath.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_dacl,
            ptr::null(),
        )
    };
    // SAFETY: `new_dacl` was LocalAlloc'd by SetEntriesInAclW; freed once now that
    // it has been applied (the OS copied it into the object's security descriptor).
    unsafe { LocalFree(new_dacl as _) };
    if err != 0 {
        // SAFETY: `prior_sd` freed once. The DACL set failed, so nothing to undo.
        unsafe { LocalFree(prior_sd as _) };
        free_sid(sid);
        return Err(SpawnError {
            ctx: "SetNamedSecurityInfo.dacl",
            code: err,
        });
    }

    // For a writable workspace, drop the object to a Low integrity label so the
    // Low-IL AppContainer worker can write to it.
    let mut set_label = false;
    if access.needs_low_label() {
        if let Err(e) = set_low_label(&wpath) {
            // Roll back the DACL grant we just applied before failing.
            let _ = restore_dacl(&wpath, prior_dacl);
            // SAFETY: `prior_sd` freed once after its `prior_dacl` was consumed.
            unsafe { LocalFree(prior_sd as _) };
            free_sid(sid);
            return Err(e);
        }
        set_label = true;
    }

    free_sid(sid);
    Ok(PathGrant {
        path: wpath,
        prior_sd,
        prior_dacl,
        prior_sacl,
        set_label,
        revoked: false,
    })
}

/// The capability-free AppContainer SID as its `S-1-…` string. Test/diagnostic
/// support for asserting an ACE targets exactly this container; not on the hot
/// path. (The SID is derived, stringified, and freed within the call.)
pub fn appcontainer_sid_string() -> Result<String, SpawnError> {
    let sid = appcontainer_sid()?;
    let r = sid_to_string(sid);
    free_sid(sid);
    r
}

/// Make an inheritable pipe (with the AppContainer-granting security descriptor)
/// and turn off inheritance on the parent's end. Returns `(child_end,
/// parent_end)`. `parent_is_write` selects which end the parent keeps.
fn make_pipe(
    parent_is_write: bool,
    psd: *mut core::ffi::c_void,
) -> Result<(HANDLE, HANDLE), SpawnError> {
    let mut sa: SECURITY_ATTRIBUTES = unsafe { core::mem::zeroed() };
    sa.nLength = core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    sa.lpSecurityDescriptor = psd; // grant the AppContainer access to the pipe
    sa.bInheritHandle = 1; // both ends inheritable; we disable the parent end next
    let mut read: HANDLE = ptr::null_mut();
    let mut write: HANDLE = ptr::null_mut();
    // SAFETY: out-params are valid; `sa` lives across the call.
    let ok = unsafe { CreatePipe(&mut read, &mut write, &sa, 0) };
    if ok == 0 {
        return Err(SpawnError::last("CreatePipe"));
    }
    let (child_end, parent_end) = if parent_is_write {
        (read, write)
    } else {
        (write, read)
    };
    // The parent's end must NOT be inherited by the worker.
    // SAFETY: parent_end is a valid handle just created.
    let ok = unsafe { SetHandleInformation(parent_end, HANDLE_FLAG_INHERIT, 0) };
    if ok == 0 {
        unsafe {
            CloseHandle(read);
            CloseHandle(write);
        }
        return Err(SpawnError::last("SetHandleInformation"));
    }
    Ok((child_end, parent_end))
}

/// Generous bounded wait for the confined worker to exit (Important #2): long
/// enough never to trip a legitimate decode in the tests, short enough to bound a
/// worker that closes stdout then **spins** within the memory cap (a plain
/// `INFINITE` wait would let such a worker hang the trusted launcher thread, and
/// kill-on-close cannot engage until the wait returns). On timeout the worker is
/// actively terminated — the active backstop — rather than waited on forever.
/// Responsive user-initiated cancel is Gate 4's concern; this is only the safety
/// net so a runaway can't hang the launcher or survive.
const WORKER_WAIT_TIMEOUT_MS: u32 = 120_000;

/// Brief grace wait after a forced `TerminateProcess` so the kill takes effect
/// before the exit code is read and the handles are released.
const WORKER_KILL_GRACE_MS: u32 = 5_000;

/// **RAII owner** of the kill-on-close Job Object + the child's process/thread
/// handles (Important #1). While `armed`, `Drop` terminates the worker (if still
/// running) and closes `job`/`pi.hThread`/`pi.hProcess` exactly once — so an
/// unwind anywhere in a driver (a panicking `drive` closure, the read loop, a
/// failed `thread::spawn`) cannot leak the job and leave the confined worker
/// alive until the long-lived parent exits. The success path calls
/// [`finish_confined`], which [`disarm`](JobGuard::disarm)s the guard and performs
/// the explicit teardown, so the handles are never double-closed.
struct JobGuard {
    job: HANDLE,
    pi: PROCESS_INFORMATION,
    armed: bool,
}

impl JobGuard {
    /// Disarm and surrender the owned handles to the success-path teardown
    /// ([`finish_confined`]). After this the guard's `Drop` is a no-op, so the
    /// returned `job`/`pi` are closed exactly once by the explicit teardown.
    fn disarm(mut self) -> (HANDLE, PROCESS_INFORMATION) {
        self.armed = false;
        // `HANDLE` and `PROCESS_INFORMATION` are `Copy`; copying them out leaves
        // `self` intact to drop harmlessly (armed == false → no close).
        (self.job, self.pi)
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        if !self.armed {
            return; // success path already took ownership via `disarm`.
        }
        // SAFETY (error/unwind path): `pi.hProcess` is the live confined child and
        // `job` the live kill-on-close Job; terminate the worker (exit code
        // irrelevant) so it does NOT survive, then close `job`/`pi.hThread`/
        // `pi.hProcess` exactly once (this guard is the sole owner once armed).
        unsafe {
            TerminateProcess(self.pi.hProcess, 1);
            CloseHandle(self.job);
            CloseHandle(self.pi.hThread);
            CloseHandle(self.pi.hProcess);
        }
    }
}

/// A live confined child after the full AppContainer + Job Object + pipe
/// [`setup_confined_child`]: a [`JobGuard`] RAII-owning the kill-on-close Job +
/// the process/thread handles, plus the parent ends of the two stdio pipes. The
/// child is already assigned to the job and **resumed**. Both drivers —
/// [`spawn_confined`] (serial) and [`spawn_confined_session`] (duplex) — obtain
/// this from the one setup site, so the confinement FFI lives in exactly one
/// place; they differ only in how they drive the two pipe ends. Teardown is via
/// [`finish_confined`] (success, disarms the guard) or [`JobGuard::drop`] (unwind);
/// the two parent ends are wrapped in `std::fs::File`s and closed by those.
struct ConfinedChild {
    guard: JobGuard,
    parent_stdin_write: HANDLE,
    parent_stdout_read: HANDLE,
}

/// Full AppContainer + Job Object + pipe **setup** shared by both confined drivers
/// (DESIGN §8.1/D30): create the capability-free AppContainer SID + security
/// capabilities, the two AppContainer-granted stdio pipes, the proc-thread
/// attribute list, then `CreateProcessW` (suspended), assign the child to a
/// no-children / memory-capped / kill-on-close Job Object, and resume it. The
/// confinement is identical regardless of how the caller drives the pipes — this
/// change is purely about I/O concurrency, not privilege. On ANY error every
/// handle created here is closed (and a created-but-unresumed child terminated)
/// before returning: no leak, no double-close.
fn setup_confined_child(
    worker_path: &Path,
    extra_args: &[&str],
    memory_cap_bytes: u64,
) -> Result<ConfinedChild, SpawnError> {
    let sid = appcontainer_sid()?;

    // Capability-free security capabilities → no network, low-privilege token.
    let mut caps: SECURITY_CAPABILITIES = unsafe { core::mem::zeroed() };
    caps.AppContainerSid = sid;
    caps.Capabilities = ptr::null_mut();
    caps.CapabilityCount = 0;

    // stdin: worker reads (child gets read end); stdout: worker writes. Both
    // pipes grant the AppContainer access via the shared security descriptor.
    let pipe_sd = appcontainer_pipe_security(sid)?;
    let pipes = (|| {
        // stdin: the PARENT writes the request, the worker reads → parent keeps
        // the write end. stdout: the parent reads the response → parent keeps the
        // read end.
        let stdin = make_pipe(true, pipe_sd)?;
        let stdout = make_pipe(false, pipe_sd)?;
        Ok((stdin, stdout))
    })();
    // The descriptor is only consulted during CreatePipe; free it now.
    // SAFETY: `pipe_sd` came from ConvertStringSecurityDescriptor (LocalAlloc'd).
    unsafe { LocalFree(pipe_sd) };
    let ((child_stdin, parent_stdin_write), (child_stdout, parent_stdout_read)) = pipes?;

    // Build the proc-thread attribute list holding the security capabilities.
    let mut attr_size: usize = 0;
    // SAFETY: first call computes the required size (returns FALSE).
    unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut attr_size) };
    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut core::ffi::c_void;
    // SAFETY: buffer is sized exactly as requested above.
    if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) } == 0 {
        let e = SpawnError::last("InitializeProcThreadAttributeList");
        close_all(&[child_stdin, parent_stdin_write, child_stdout, parent_stdout_read]);
        return Err(e);
    }
    // SAFETY: `caps` outlives CreateProcessW below; the attribute references it.
    let upd = unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &caps as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<SECURITY_CAPABILITIES>(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if upd == 0 {
        let e = SpawnError::last("UpdateProcThreadAttribute");
        unsafe { DeleteProcThreadAttributeList(attr_list) };
        close_all(&[child_stdin, parent_stdin_write, child_stdout, parent_stdout_read]);
        return Err(e);
    }

    let mut si: STARTUPINFOEXW = unsafe { core::mem::zeroed() };
    si.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = child_stdin;
    si.StartupInfo.hStdOutput = child_stdout;
    // stderr is DELIBERATELY NOT the stdout pipe: stdout carries the length-prefixed
    // FRAME protocol (one-shot proto response / duplex `WorkerMsg` stream), and a
    // dying worker's diagnostics (a Rust panic message, the alloc-error handler's
    // "memory allocation of N bytes failed" before `abort`) must NEVER be merged onto
    // it. Merging them previously corrupted the frame stream on abort: the diagnostic
    // text's leading bytes parsed as an over-ceiling frame length, so the launcher
    // read a worker DEATH as a parent-side `Protective` cutoff (over-ceiling frame) and
    // the resilient driver refused to respawn — a confined-worker abort (F1 rav1d panic
    // / F2 stsz-OOM Job-kill) lost the rest of the window instead of skipping just the
    // culprit fragment. With stderr routed to NULL (the worker has STARTF_USESTDHANDLES
    // set, so this is a real "no stderr device", not console inheritance), an abort now
    // surfaces on the FRAME pipe as a clean truncation/EOF which — combined with the
    // non-zero/killed process exit code — classifies as `WorkerGone` (resumable), so
    // the per-fragment skip+respawn works. This does NOT weaken any confinement (the
    // worker simply has nowhere to write diagnostics) and does NOT touch the
    // over-ceiling→`Protective` defense against a LIVE worker streaming a bomb-frame on
    // the real frame pipe.
    si.StartupInfo.hStdError = ptr::null_mut();
    si.lpAttributeList = attr_list;

    let app = wide(&worker_path.to_string_lossy());
    let mut cmdline = {
        let mut s = String::new();
        s.push('"');
        s.push_str(&worker_path.to_string_lossy());
        s.push('"');
        for a in extra_args {
            s.push(' ');
            s.push('"');
            s.push_str(a); // selftest flags/paths contain no embedded quotes
            s.push('"');
        }
        wide(&s)
    };

    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: all buffers (app, cmdline, si, attr_buf, caps, sid) live across the
    // call; handles are valid; flags request an extended, suspended start.
    let created = unsafe {
        CreateProcessW(
            app.as_ptr(),
            cmdline.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1, // inherit handles (the child pipe ends)
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(),
            &si as *const STARTUPINFOEXW as *const STARTUPINFOW,
            &mut pi,
        )
    };
    unsafe { DeleteProcThreadAttributeList(attr_list) };
    // The child has inherited its pipe ends; the parent no longer needs them.
    close_all(&[child_stdin, child_stdout]);
    if created == 0 {
        let e = SpawnError::last("CreateProcessW");
        close_all(&[parent_stdin_write, parent_stdout_read]);
        return Err(e);
    }

    // Job Object: one process only (no children), memory-capped, kill-on-close. On
    // any job-setup failure the child is created-but-suspended (never resumed):
    // terminate + close it and the parent pipe ends so nothing leaks.
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        let e = SpawnError::last("CreateJobObject");
        teardown_unstarted(&pi, &[parent_stdin_write, parent_stdout_read]);
        return Err(e);
    }
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { core::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.BasicLimitInformation.ActiveProcessLimit = 1;
    info.ProcessMemoryLimit = memory_cap_bytes as usize;
    let set = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if set == 0 {
        let e = SpawnError::last("SetInformationJobObject");
        unsafe { CloseHandle(job) };
        teardown_unstarted(&pi, &[parent_stdin_write, parent_stdout_read]);
        return Err(e);
    }
    if unsafe { AssignProcessToJobObject(job, pi.hProcess) } == 0 {
        let e = SpawnError::last("AssignProcessToJobObject");
        unsafe { CloseHandle(job) };
        teardown_unstarted(&pi, &[parent_stdin_write, parent_stdout_read]);
        return Err(e);
    }
    // Now that confinement is in place, let the worker run.
    unsafe { ResumeThread(pi.hThread) };

    // From here on the job + child are owned by an armed RAII guard, so any later
    // unwind in a driver terminates the worker and closes the handles (Important #1).
    Ok(ConfinedChild {
        guard: JobGuard {
            job,
            pi,
            armed: true,
        },
        parent_stdin_write,
        parent_stdout_read,
    })
}

/// Success-path teardown: disarm the [`JobGuard`], wait (bounded) for the confined
/// child to exit, read its exit code, then close the job (kill-on-close — a no-op
/// once the process already exited, but releases the job) and the `pi` handles.
/// Closes `job`/`pi.hThread`/`pi.hProcess` exactly once (the guard is disarmed, so
/// there is no double-close).
///
/// The wait is **bounded** ([`WORKER_WAIT_TIMEOUT_MS`], Important #2): a compromised
/// worker that closes stdout then spins (within the memory cap, never exiting)
/// would block the trusted launcher thread forever under a plain `INFINITE` wait,
/// and kill-on-close cannot engage until the wait returns. On `WAIT_TIMEOUT` the
/// worker is actively terminated (then briefly waited on) rather than relied upon
/// to exit voluntarily.
fn finish_confined(guard: JobGuard) -> u32 {
    finish_confined_with_timeout(guard, WORKER_WAIT_TIMEOUT_MS)
}

/// [`finish_confined`] with an explicit forced-kill timeout. The worker path uses
/// the fixed [`WORKER_WAIT_TIMEOUT_MS`] (via [`finish_confined`], unchanged); the
/// ffmpeg ingest path ([`spawn_confined_exe`]) passes a per-job bound, because a
/// legitimate large/long transcode can exceed two minutes and must not be wrongly
/// killed — yet the wait must still be FINITE (a DoS bound), then force-killed.
fn finish_confined_with_timeout(guard: JobGuard, timeout_ms: u32) -> u32 {
    let (job, pi) = guard.disarm();
    // SAFETY: `pi.hProcess` is the live confined child; wait up to the bound, then
    // — on timeout — actively kill it so a spinning child can't hang the launcher.
    unsafe {
        if WaitForSingleObject(pi.hProcess, timeout_ms) == WAIT_TIMEOUT {
            TerminateProcess(pi.hProcess, 1);
            // Let the kill land before reading the exit code / releasing handles.
            WaitForSingleObject(pi.hProcess, WORKER_KILL_GRACE_MS);
        }
    }
    let mut code: u32 = 0;
    // SAFETY: `pi.hProcess` is still open; `&mut code` is valid (a failed read
    // leaves `code` at 0).
    unsafe { GetExitCodeProcess(pi.hProcess, &mut code) };
    // Closing the job (kill-on-close) after the process already exited is a no-op
    // for it but releases the job.
    // SAFETY: `job` and the `pi` handles are each closed exactly once here.
    unsafe {
        CloseHandle(job);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    code
}

/// Clean up a created-but-never-resumed child after a Job-setup failure: kill the
/// suspended process (closing its handles alone would orphan it), close its
/// handles, and close the parent pipe ends — no leak, no double-close.
fn teardown_unstarted(pi: &PROCESS_INFORMATION, parent_ends: &[HANDLE]) {
    // SAFETY: `pi.hProcess` is a valid, suspended child just created above;
    // terminate it (exit code irrelevant) before releasing the handles so no
    // suspended orphan remains. Each handle is closed exactly once.
    unsafe {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    close_all(parent_ends);
}

/// Spawn the `media-worker` binary at `worker_path` with `extra_args`, confined to
/// an AppContainer (no network/key access) + a Job Object (no child processes,
/// memory-capped, kill-on-close). `stdin_data` is written to the worker's stdin;
/// its stdout is captured. **Serial** I/O (write-all-then-read-all) — for the
/// one-shot request/response worker; the duplex session uses
/// [`spawn_confined_session`].
pub fn spawn_confined(
    worker_path: &Path,
    extra_args: &[&str],
    stdin_data: &[u8],
    memory_cap_bytes: u64,
) -> Result<ConfinedOutput, SpawnError> {
    let ConfinedChild {
        guard,
        parent_stdin_write,
        parent_stdout_read,
    } = setup_confined_child(worker_path, extra_args, memory_cap_bytes)?;

    // `guard` RAII-owns the job + child until `finish_confined` disarms it: if the
    // serial I/O below unwinds, the worker is terminated and the handles closed.
    // Stream stdin then EOF, capture stdout — via std::fs::File over the
    // parent handle ends so the I/O itself isn't FFI.
    {
        use std::io::Write;
        // SAFETY: we own parent_stdin_write; File takes ownership and closes it.
        let mut w = unsafe { std::fs::File::from_raw_handle(parent_stdin_write as _) };
        let _ = w.write_all(stdin_data);
        // drop(w) closes the pipe → worker sees EOF.
    }
    let mut out = Vec::new();
    {
        use std::io::Read;
        // SAFETY: we own parent_stdout_read; File takes ownership and closes it.
        let mut r = unsafe { std::fs::File::from_raw_handle(parent_stdout_read as _) };
        let _ = r.read_to_end(&mut out);
    }

    let exit_code = finish_confined(guard);
    Ok(ConfinedOutput {
        exit_code,
        stdout: out,
    })
}

/// Like [`spawn_confined`] but drives a **persistent duplex session** over the
/// SAME AppContainer + Job Object + pipe setup (no weakening of confinement —
/// only the I/O concurrency differs; `extra_args` selects the worker mode, e.g.
/// `--video-session` for a real session or a `--selftest-*` probe for the duplex
/// containment differential). The two parent pipe ends are wrapped in
/// `std::fs::File`s (so the duplex I/O itself is NOT FFI) and handed to `drive`,
/// which streams framed requests on a writer thread while concurrently reading
/// responses — no deadlock. When `drive` returns (both pipe ends dropped → the
/// worker sees EOF), the worker is waited on (bounded — see [`finish_confined`]),
/// its exit code read, and the Job Object closed (kill-on-close tears the session
/// worker down on session end / error). A panic in `drive` unwinds through the
/// armed [`JobGuard`], which terminates the worker and closes the handles
/// (Important #1) — the leaked job would otherwise leave it alive. Returns
/// `drive`'s result paired with the worker exit code.
pub fn spawn_confined_session<T>(
    worker_path: &Path,
    extra_args: &[&str],
    memory_cap_bytes: u64,
    drive: impl FnOnce(std::fs::File, std::fs::File) -> T,
) -> Result<(T, u32), SpawnError> {
    let ConfinedChild {
        guard,
        parent_stdin_write,
        parent_stdout_read,
    } = setup_confined_child(worker_path, extra_args, memory_cap_bytes)?;

    // SAFETY: we own both parent ends; each File takes ownership of one and closes
    // it exactly once (when `drive` drops it). The duplex framing runs inside
    // `drive` over these Files, so the I/O itself isn't FFI. `guard` stays armed
    // across `drive`, so an unwind there still tears the worker down.
    let writer = unsafe { std::fs::File::from_raw_handle(parent_stdin_write as _) };
    let reader = unsafe { std::fs::File::from_raw_handle(parent_stdout_read as _) };

    let result = drive(writer, reader);

    let exit_code = finish_confined(guard);
    Ok((result, exit_code))
}

fn close_all(handles: &[HANDLE]) {
    for &h in handles {
        if !h.is_null() && h != INVALID_HANDLE_VALUE {
            // SAFETY: each handle was produced by a Win32 call above and is closed
            // exactly once.
            unsafe { CloseHandle(h) };
        }
    }
}

// ===========================================================================
// Confined arbitrary-exe spawn for the author-side ffmpeg ingest (Task 2.2, D-2).
//
// `ffmpeg.exe` is the #1 RCE surface on the author side: it parses arbitrary,
// attacker-authored source media. It is run inside the SAME confinement the decode
// worker uses — the capability-free AppContainer SID (no network capability, a
// low-IL token that cannot read the user's keys) + a Job Object (ActiveProcessLimit
// = 1 → no child processes, a hard memory cap, kill-on-job-close) — but with a
// DIFFERENT stdio shape: ffmpeg's MP4 muxer writes `moov` last and so cannot stream
// to a pipe (per the Phase-0 ratification it writes a TEMP FILE), therefore media
// never crosses stdio. stdin and stdout are the NUL device; stderr is a BOUNDED
// capture pipe (ffmpeg's diagnostics, useful for a sanitized failure log, capped so
// a verbose/hostile ffmpeg can't OOM the parent). Filesystem access is scoped to
// exactly the caller's per-job dir via the Task-2.1 RAII path grant, revoked on
// every exit path.
// ===========================================================================

/// Hard cap on the captured ffmpeg stderr tail (head-kept): a verbose or hostile
/// ffmpeg cannot drive an unbounded allocation in the trusted parent through its
/// diagnostics stream. 64 KiB is ample for the final error lines that matter.
pub const FFMPEG_STDERR_CAP_BYTES: usize = 64 * 1024;

/// Encode an `OsStr` to a NUL-terminated wide buffer (for `lpApplicationName`).
fn wide_os(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Append `arg` to a command-line wide buffer, quoted per the `CommandLineToArgvW`
/// rules (so a path with spaces, embedded quotes, or trailing backslashes round-
/// trips to exactly one argv element). Always double-quotes the argument.
fn append_quoted_wide(out: &mut Vec<u16>, arg: &OsStr) {
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    out.push(QUOTE);
    let mut backslashes: usize = 0;
    for c in arg.encode_wide() {
        if c == BACKSLASH {
            backslashes += 1;
        } else if c == QUOTE {
            // Escape the run of backslashes (double them) then the embedded quote.
            for _ in 0..(backslashes * 2 + 1) {
                out.push(BACKSLASH);
            }
            out.push(QUOTE);
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push(BACKSLASH);
            }
            backslashes = 0;
            out.push(c);
        }
    }
    // Double a trailing run of backslashes so the closing quote is not escaped.
    for _ in 0..(backslashes * 2) {
        out.push(BACKSLASH);
    }
    out.push(QUOTE);
}

/// Open the **NUL** device as an inheritable handle for a confined child's stdin
/// (`write = false`, immediate EOF on read) or stdout (`write = true`, discard).
/// Media never crosses stdio (it goes to the granted output file), so the child's
/// stdin/stdout are NUL — bounded by construction, no parent capture. NUL has a
/// world-permissive DACL, so the inherited handle is usable by the low-IL
/// AppContainer without an explicit grant.
fn open_nul(write: bool) -> Result<HANDLE, SpawnError> {
    let name = wide("NUL");
    let mut sa: SECURITY_ATTRIBUTES = unsafe { core::mem::zeroed() };
    sa.nLength = core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    sa.lpSecurityDescriptor = ptr::null_mut();
    sa.bInheritHandle = 1; // the child must inherit this stdio handle.
    let access = if write { GENERIC_WRITE } else { GENERIC_READ };
    // SAFETY: `name` is a valid NUL-terminated wide string; `sa` lives across the
    // call; opening the existing NUL device returns an owned, inheritable handle.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(SpawnError::last("CreateFileW.NUL"));
    }
    Ok(h)
}

/// A live confined arbitrary-exe child after [`setup_confined_exe_child`]: the
/// kill-on-close [`JobGuard`] (RAII-owning the Job + process/thread handles) plus
/// the parent's read end of the stderr capture pipe. stdin/stdout are NUL (not
/// owned here — the child inherited them and the parent closed its copies).
struct ConfinedExeChild {
    guard: JobGuard,
    parent_stderr_read: HANDLE,
}

/// AppContainer + Job Object + NUL-stdio + stderr-capture setup for a confined
/// arbitrary exe (the ffmpeg sibling of [`setup_confined_child`]): same
/// capability-free SID + `SECURITY_CAPABILITIES` + proc-thread attribute list +
/// no-children / memory-capped / kill-on-close Job, but stdin = NUL, stdout = NUL,
/// stderr = an AppContainer-granted capture pipe (ffmpeg has no framed protocol to
/// corrupt — only diagnostics — so unlike the worker its stderr IS captured). On
/// ANY error every handle made here is closed (and a created-but-unresumed child
/// terminated) and the SID freed before returning: no leak, no double-close.
fn setup_confined_exe_child(
    program: &Path,
    args: &[OsString],
    memory_cap_bytes: u64,
) -> Result<ConfinedExeChild, SpawnError> {
    // Declared FIRST so it drops LAST: the SID must outlive `caps` / the attribute
    // list / `CreateProcessW`. Frees the SID on every exit path below.
    let sid_guard = SidGuard(appcontainer_sid()?);
    let sid = sid_guard.0;

    // Capability-free security capabilities → no network, low-privilege token.
    let mut caps: SECURITY_CAPABILITIES = unsafe { core::mem::zeroed() };
    caps.AppContainerSid = sid;
    caps.Capabilities = ptr::null_mut();
    caps.CapabilityCount = 0;

    // stderr capture pipe: the child WRITES diagnostics, the parent READS them. The
    // pipe is granted to the container SID (same pattern as the worker pipes).
    let pipe_sd = appcontainer_pipe_security(sid)?;
    let pipe = make_pipe(false, pipe_sd);
    // SAFETY: `pipe_sd` came from ConvertStringSecurityDescriptor (LocalAlloc'd);
    // only consulted during CreatePipe, freed now.
    unsafe { LocalFree(pipe_sd) };
    let (child_stderr, parent_stderr_read) = pipe?;

    // stdin = NUL (immediate EOF), stdout = NUL (discard). On failure close what we
    // have so far (the stderr pipe ends + any NUL handle already opened).
    let child_stdin = match open_nul(false) {
        Ok(h) => h,
        Err(e) => {
            close_all(&[child_stderr, parent_stderr_read]);
            return Err(e);
        }
    };
    let child_stdout = match open_nul(true) {
        Ok(h) => h,
        Err(e) => {
            close_all(&[child_stdin, child_stderr, parent_stderr_read]);
            return Err(e);
        }
    };

    // The EXACT set of handles the confined child may inherit. `CreateProcessW` is
    // called with `bInheritHandles = TRUE`, so without an explicit allow-list the
    // child would inherit EVERY inheritable handle open in the key-holding parent —
    // an ambient-inheritance gap across the RCE boundary. `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
    // restricts inheritance to precisely these three: NUL stdin, NUL stdout, and the
    // stderr-write pipe end (all already inheritable — NUL opened inheritable, the
    // pipe end inheritable via `make_pipe`). This array MUST outlive `CreateProcessW`
    // (the attribute holds a pointer into it), so it is a local that lives to the end
    // of the function.
    let inherit_handles: [HANDLE; 3] = [child_stdin, child_stdout, child_stderr];

    // Build the proc-thread attribute list holding BOTH the security capabilities and
    // the handle allow-list (TWO attributes).
    let mut attr_size: usize = 0;
    // SAFETY: first call computes the required size (returns FALSE).
    unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut attr_size) };
    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut core::ffi::c_void;
    // SAFETY: buffer is sized exactly as requested above.
    if unsafe { InitializeProcThreadAttributeList(attr_list, 2, 0, &mut attr_size) } == 0 {
        let e = SpawnError::last("InitializeProcThreadAttributeList");
        close_all(&[child_stdin, child_stdout, child_stderr, parent_stderr_read]);
        return Err(e);
    }
    // SAFETY: `caps` outlives CreateProcessW below; the attribute references it.
    let upd = unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &caps as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<SECURITY_CAPABILITIES>(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if upd == 0 {
        let e = SpawnError::last("UpdateProcThreadAttribute.caps");
        unsafe { DeleteProcThreadAttributeList(attr_list) };
        close_all(&[child_stdin, child_stdout, child_stderr, parent_stderr_read]);
        return Err(e);
    }
    // SAFETY: `inherit_handles` outlives CreateProcessW below; the attribute holds a
    // pointer into it for exactly its `len()*size_of::<HANDLE>()` bytes.
    let upd_hl = unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherit_handles.as_ptr() as *const core::ffi::c_void,
            core::mem::size_of_val(&inherit_handles),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if upd_hl == 0 {
        let e = SpawnError::last("UpdateProcThreadAttribute.handle_list");
        unsafe { DeleteProcThreadAttributeList(attr_list) };
        close_all(&[child_stdin, child_stdout, child_stderr, parent_stderr_read]);
        return Err(e);
    }

    let mut si: STARTUPINFOEXW = unsafe { core::mem::zeroed() };
    si.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    // Media never crosses stdio (it goes to the granted output file): stdin/stdout
    // are NUL, and ONLY stderr is captured (bounded). There is no framed protocol on
    // any stream for ffmpeg's diagnostics to corrupt.
    si.StartupInfo.hStdInput = child_stdin;
    si.StartupInfo.hStdOutput = child_stdout;
    si.StartupInfo.hStdError = child_stderr;
    si.lpAttributeList = attr_list;

    // Build the command line: quoted program + each quoted argv element (paths may
    // contain spaces / unicode — `OsStr`-faithful wide quoting, no lossy String).
    let app = wide_os(program.as_os_str());
    let mut cmdline: Vec<u16> = Vec::new();
    append_quoted_wide(&mut cmdline, program.as_os_str());
    for a in args {
        cmdline.push(b' ' as u16);
        append_quoted_wide(&mut cmdline, a);
    }
    cmdline.push(0); // NUL-terminate the (mutable) command line.

    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: all buffers (app, cmdline, si, attr_buf, caps, sid) live across the
    // call; the std handles are valid; flags request an extended, suspended start.
    let created = unsafe {
        CreateProcessW(
            app.as_ptr(),
            cmdline.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1, // inherit handles (the child NUL stdio + the child stderr write end)
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(),
            &si as *const STARTUPINFOEXW as *const STARTUPINFOW,
            &mut pi,
        )
    };
    unsafe { DeleteProcThreadAttributeList(attr_list) };
    // The child has inherited its stdio + stderr-write ends; the parent's copies are
    // no longer needed (closing the parent's stderr-write copy is what lets the
    // capture reader see EOF once the child exits).
    close_all(&[child_stdin, child_stdout, child_stderr]);
    if created == 0 {
        let e = SpawnError::last("CreateProcessW");
        close_all(&[parent_stderr_read]);
        return Err(e);
    }

    // Job Object: one process only (no children), memory-capped, kill-on-close. On
    // any job-setup failure the child is created-but-suspended (never resumed):
    // terminate + close it and the parent pipe end so nothing leaks.
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        let e = SpawnError::last("CreateJobObject");
        teardown_unstarted(&pi, &[parent_stderr_read]);
        return Err(e);
    }
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { core::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.BasicLimitInformation.ActiveProcessLimit = 1;
    info.ProcessMemoryLimit = memory_cap_bytes as usize;
    let set = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if set == 0 {
        let e = SpawnError::last("SetInformationJobObject");
        unsafe { CloseHandle(job) };
        teardown_unstarted(&pi, &[parent_stderr_read]);
        return Err(e);
    }
    if unsafe { AssignProcessToJobObject(job, pi.hProcess) } == 0 {
        let e = SpawnError::last("AssignProcessToJobObject");
        unsafe { CloseHandle(job) };
        teardown_unstarted(&pi, &[parent_stderr_read]);
        return Err(e);
    }
    // Now that confinement is in place, let ffmpeg run.
    unsafe { ResumeThread(pi.hThread) };

    Ok(ConfinedExeChild {
        guard: JobGuard {
            job,
            pi,
            armed: true,
        },
        parent_stderr_read,
    })
    // `sid_guard` drops here (and on every early-error return above), freeing the
    // SID now that the process is created / the spawn has failed.
}

/// Drain a confined child's stderr `File` to EOF, retaining only the first `cap`
/// bytes (head-kept) but ALWAYS continuing to read past the cap so the child never
/// blocks on a full pipe (which would otherwise defeat the bounded-wait kill). A
/// read error ends the drain (the pipe broke = the child died). Returns the bounded
/// tail.
fn read_bounded_stderr(mut f: std::fs::File, cap: usize) -> Vec<u8> {
    use std::io::Read;
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match f.read(&mut tmp) {
            Ok(0) => break, // EOF — the child closed (or was killed and closed) stderr.
            Ok(n) => {
                if out.len() < cap {
                    let take = n.min(cap - out.len());
                    out.extend_from_slice(&tmp[..take]);
                }
                // Beyond the cap: keep draining + discarding so the child can't block.
            }
            Err(_) => break,
        }
    }
    out
}

/// Spawn `program` with `args` **confined** (Task 2.2, D-2): inside the
/// capability-free AppContainer (no network, a low-IL token that cannot read the
/// user's keys) + a Job Object (no child processes, `memory_cap_bytes`,
/// kill-on-close + a bounded-wait-then-kill safety net), with stdin/stdout = NUL
/// and a BOUNDED stderr capture. `grants` are applied (Task-2.1
/// [`grant_path_to_appcontainer`]) BEFORE the spawn and held — as RAII
/// [`PathGrant`]s — across the wait, then revoked when this function returns on
/// EVERY path (success, non-zero exit, timeout-kill, or a panic unwinding through
/// the guard vector). Typically a single `(per_job_dir, GrantAccess::ReadWrite)`
/// grant scopes the confined ffmpeg to exactly its input + output files.
///
/// `timeout_ms` is the per-job forced-kill bound (a FINITE DoS ceiling): the child
/// is waited on up to this long, then actively terminated. Sized by the caller for
/// a legitimate large/long transcode (the worker path's fixed 2-minute bound is too
/// short for universal video ingest) — generous but never `INFINITE`.
///
/// Returns ffmpeg's exit code + the bounded stderr tail. The CALLER (Phase 3) then
/// reads the output file from the granted dir.
pub fn spawn_confined_exe(
    program: &Path,
    args: &[OsString],
    grants: &[(&Path, GrantAccess)],
    memory_cap_bytes: u64,
    timeout_ms: u32,
) -> Result<ConfinedExeOutput, SpawnError> {
    // Apply the scoped path grants up front; the RAII guards are held for the whole
    // spawn and revoked when `_grants` drops (success OR any early `?` / panic).
    let mut grant_guards: Vec<PathGrant> = Vec::with_capacity(grants.len());
    for (path, access) in grants {
        grant_guards.push(grant_path_to_appcontainer(path, *access)?);
    }

    let ConfinedExeChild {
        guard,
        parent_stderr_read,
    } = setup_confined_exe_child(program, args, memory_cap_bytes)?;

    // Drain stderr (bounded) on a reader thread so a verbose ffmpeg can't block on a
    // full pipe — leaving the bounded wait + kill on THIS thread to bound a runaway.
    // SAFETY: we own `parent_stderr_read`; the `File` takes ownership and closes it
    // exactly once (when the reader thread drops it). `File` is `Send`, so it (not
    // the raw `HANDLE`) is what crosses to the thread.
    let stderr_file = unsafe { std::fs::File::from_raw_handle(parent_stderr_read as _) };
    let reader =
        std::thread::spawn(move || read_bounded_stderr(stderr_file, FFMPEG_STDERR_CAP_BYTES));

    // `guard` RAII-owns the Job + child until `finish_confined` disarms it: a bounded
    // wait, a kill on timeout, the exit code, and the handle teardown. Once it
    // returns, the child is dead → its stderr write end is closed → the reader hits
    // EOF and the join completes.
    let exit_code = finish_confined_with_timeout(guard, timeout_ms);
    let stderr_tail = reader.join().unwrap_or_default();

    Ok(ConfinedExeOutput {
        exit_code,
        stderr_tail,
    })
    // `grant_guards` drops here → every path grant is revoked (DACL + label restored).
}
