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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

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
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
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
    /// `true` iff the run was terminated because the caller's `cancel` flag was set
    /// (a user-initiated / app-shutdown cancel) — a DISTINCT, benign outcome the
    /// caller maps to a `cancelled` error, NOT the sanitized failure a stall/backstop
    /// kill or a non-zero exit produces.
    pub cancelled: bool,
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

/// Poll interval for the cancellable confined-wait loops (Task B/C). Each iteration
/// BLOCKS on `WaitForSingleObject` for this long (so it is NOT a hot spin — the CPU
/// is idle while the child runs), then re-checks the cancel flag / stall clock /
/// absolute backstop. 150 ms is responsive to a user cancel without busy-waiting.
const CONFINED_POLL_INTERVAL_MS: u32 = 150;

/// A never-set cancel flag for the confined spawns that have no user-cancel channel
/// (the decode worker + the duplex session). Passing it keeps ONE cancellable wait
/// implementation ([`finish_confined_watchdog`]) without a second, near-identical
/// non-cancellable copy — the flag simply never becomes true, so the behavior is the
/// prior bounded-wait-then-kill.
static NEVER_CANCEL: AtomicBool = AtomicBool::new(false);

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
/// child is already assigned to the job and **resumed**. [`spawn_confined`]
/// (serial) obtains this from the one setup site, so the confinement FFI lives in
/// exactly one place. Teardown is via [`finish_confined`] (success, disarms the
/// guard) or [`JobGuard::drop`] (unwind); the two parent ends are wrapped in
/// `std::fs::File`s and closed by those.
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
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
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

/// Success-path teardown: disarm the [`JobGuard`], wait (bounded, cancellable) for
/// the confined child to exit, read its exit code, then close the job (kill-on-close
/// — a no-op once the process already exited, but releases the job) and the `pi`
/// handles. Closes `job`/`pi.hThread`/`pi.hProcess` exactly once (the guard is
/// disarmed, so there is no double-close).
///
/// The wait is **bounded** ([`WORKER_WAIT_TIMEOUT_MS`], Important #2): a compromised
/// worker that closes stdout then spins (within the memory cap, never exiting)
/// would block the trusted launcher thread forever under a plain `INFINITE` wait,
/// and kill-on-close cannot engage until the wait returns. On timeout the worker is
/// actively terminated (then briefly waited on) rather than relied upon to exit
/// voluntarily. `cancel` is additionally polled (Task C) so a user cancel / app
/// shutdown tears the re-mux worker down promptly; the decode/session paths pass
/// [`NEVER_CANCEL`] to keep the prior behavior.
fn finish_confined(guard: JobGuard, cancel: &AtomicBool) -> u32 {
    // A never-advancing progress clock ⇒ the "stall" bound collapses to a plain
    // bounded wait of `WORKER_WAIT_TIMEOUT_MS`, matching the worker path's prior
    // fixed wait, while still polling `cancel`.
    let last_advance = AtomicU64::new(0);
    let start = Instant::now();
    finish_confined_watchdog(
        guard,
        &last_advance,
        start,
        WORKER_WAIT_TIMEOUT_MS,
        WORKER_WAIT_TIMEOUT_MS,
        cancel,
    )
    .0
}

/// Cancellable, progress-aware teardown poll loop (Task B/C) shared by the worker
/// path ([`finish_confined`], via a never-advancing clock) and the ffmpeg ingest
/// path ([`spawn_confined_exe`], with a live `-progress` clock). Disarms the guard,
/// then loops on a bounded `WaitForSingleObject`:
/// * child exited → done;
/// * `cancel` set → `TerminateProcess` + return `cancelled = true` (a DISTINCT,
///   benign outcome);
/// * `now - last_advance >= stall_timeout_ms` → STALL kill (progress-based, Task B):
///   the child made no forward progress for the stall window;
/// * `now >= max_total_ms` → absolute BACKSTOP kill (bounds a progress-spammer that
///   keeps advancing forever).
///
/// After any kill it briefly waits ([`WORKER_KILL_GRACE_MS`]) so the kill lands
/// before the exit code is read and the handles released. Returns
/// `(exit_code, cancelled)`; a stall/backstop kill leaves `cancelled = false` so the
/// caller maps it to the sanitized failure (non-zero exit), while a `cancelled` run
/// is mapped to the distinct `cancelled` error upstream.
fn finish_confined_watchdog(
    guard: JobGuard,
    last_advance_ms: &AtomicU64,
    start: Instant,
    stall_timeout_ms: u32,
    max_total_ms: u32,
    cancel: &AtomicBool,
) -> (u32, bool) {
    let (job, pi) = guard.disarm();
    // Start the stall clock at spawn: no progress at all within the stall window is
    // itself a stall.
    last_advance_ms.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
    let mut cancelled = false;
    loop {
        // SAFETY: `pi.hProcess` is the live confined child; a bounded blocking wait
        // (idle CPU) so the loop is responsive to cancel without a hot spin.
        let w = unsafe { WaitForSingleObject(pi.hProcess, CONFINED_POLL_INTERVAL_MS) };
        if w != WAIT_TIMEOUT {
            break; // WAIT_OBJECT_0 (exited) or WAIT_FAILED — stop waiting.
        }
        let now = start.elapsed().as_millis() as u64;
        let stalled = now.saturating_sub(last_advance_ms.load(Ordering::Relaxed))
            >= stall_timeout_ms as u64;
        let over_backstop = now >= max_total_ms as u64;
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
        } else if !stalled && !over_backstop {
            continue; // still making progress within both bounds — keep waiting.
        }
        // Cancel, stall, or backstop → actively terminate the confined child.
        // SAFETY: `pi.hProcess` is the live child; kill it, then briefly wait so the
        // kill lands before the exit code is read.
        unsafe {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, WORKER_KILL_GRACE_MS);
        }
        break;
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
    (code, cancelled)
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

/// Spawn a confined worker binary at `worker_path` with `extra_args`, confined to
/// an AppContainer (no network/key access) + a Job Object (no child processes,
/// memory-capped, kill-on-close). `stdin_data` is written to the worker's stdin;
/// its stdout is captured. **Serial** I/O (write-all-then-read-all) — for the
/// one-shot request/response worker.
pub fn spawn_confined(
    worker_path: &Path,
    extra_args: &[&str],
    stdin_data: &[u8],
    memory_cap_bytes: u64,
) -> Result<ConfinedOutput, SpawnError> {
    spawn_confined_inner(worker_path, extra_args, stdin_data, memory_cap_bytes, &NEVER_CANCEL)
}

/// Like [`spawn_confined`] but with a caller-owned `cancel` flag polled during the
/// bounded exit wait (Task C): the author-side re-mux worker
/// ([`crate::TranscodeLauncher`]) passes the same cancel token as the ffmpeg step so
/// a user cancel / app shutdown tears a slow re-mux down promptly instead of waiting
/// out the full bound. Confinement is byte-identical to [`spawn_confined`] — only
/// the wait observes `cancel`.
pub fn spawn_confined_cancellable(
    worker_path: &Path,
    extra_args: &[&str],
    stdin_data: &[u8],
    memory_cap_bytes: u64,
    cancel: &AtomicBool,
) -> Result<ConfinedOutput, SpawnError> {
    spawn_confined_inner(worker_path, extra_args, stdin_data, memory_cap_bytes, cancel)
}

fn spawn_confined_inner(
    worker_path: &Path,
    extra_args: &[&str],
    stdin_data: &[u8],
    memory_cap_bytes: u64,
    cancel: &AtomicBool,
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

    let exit_code = finish_confined(guard, cancel);
    Ok(ConfinedOutput {
        exit_code,
        stdout: out,
    })
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

/// Hard cap on the in-progress line-accumulation buffer used to parse ffmpeg's
/// per-line `-progress` output (Task A). A real `key=value` progress line or the
/// `Duration:` banner is well under this; a longer diagnostic line simply overflows
/// and is dropped at the next newline (it can't be a progress line anyway), so the
/// per-line parser is BOUNDED — no unbounded buffering regardless of ffmpeg output.
const MAX_PROGRESS_LINE_BYTES: usize = 4096;

/// Live progress parsed from ffmpeg's `-progress pipe:2` stream (Task A). Carries
/// ONLY a coarse percent + the elapsed encoded-time milliseconds — NO diagnostic
/// text, paths, or decode oracle — so nothing but sanitized progress can cross the
/// trust seam when a caller forwards it to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FfmpegProgress {
    /// Completion percent in `0..=100` (saturating), or `None` when the source
    /// `Duration` has not yet been observed (percent is unknowable).
    pub percent: Option<u8>,
    /// ffmpeg's elapsed `out_time` in milliseconds.
    pub out_time_ms: u64,
}

/// One classified line from ffmpeg's stderr (banner + `-progress` stream). Produced
/// by the pure [`parse_ffmpeg_progress_line`]; consumed by [`handle_progress_line`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FfmpegLine {
    /// The source total, in ms, from a `Duration: HH:MM:SS.ff` banner line.
    Duration(u64),
    /// Elapsed encoded time, in ms, from `out_time_us=`/`out_time_ms=`/`out_time=`.
    OutTime(u64),
    /// `progress=continue|end` — the end of one progress block ⇒ emit a sample.
    Tick,
    /// Nothing of interest.
    Ignore,
}

/// Parse an ffmpeg `H:MM:SS(.frac)` timecode into milliseconds. Fractional seconds
/// are read to millisecond precision (extra digits truncated). Pure + total (no
/// panics on malformed input — returns `None`).
fn parse_hms_ms(tc: &str) -> Option<u64> {
    let mut parts = tc.split(':');
    let h = parts.next()?;
    let m = parts.next()?;
    let s = parts.next()?;
    if parts.next().is_some() {
        return None; // more than 3 colon-separated fields — not a timecode.
    }
    let h: u64 = h.trim().parse().ok()?;
    let m: u64 = m.trim().parse().ok()?;
    if m >= 60 {
        return None;
    }
    let (sec, frac_ms) = match s.split_once('.') {
        Some((whole, frac)) => {
            let mut ms = 0u64;
            let mut scale = 100u64; // first frac digit = hundreds of ms
            for ch in frac.chars().take(3) {
                let d = ch.to_digit(10)? as u64;
                ms += d * scale;
                scale /= 10;
            }
            (whole, ms)
        }
        None => (s, 0),
    };
    let sec: u64 = sec.trim().parse().ok()?;
    if sec >= 60 {
        return None;
    }
    Some(((h * 60 + m) * 60 + sec) * 1000 + frac_ms)
}

/// Extract the source total (ms) from an ffmpeg banner line that contains
/// `Duration: HH:MM:SS.ff, ...`. Returns `None` for a line without a parsable
/// `Duration:` (including `Duration: N/A`). Pure + total.
fn parse_ffmpeg_duration_line(line: &str) -> Option<u64> {
    let idx = line.find("Duration:")?;
    let rest = line[idx + "Duration:".len()..].trim_start();
    let tc = rest.split([',', ' ']).next()?.trim();
    if tc.is_empty() || tc.eq_ignore_ascii_case("N/A") {
        return None;
    }
    parse_hms_ms(tc)
}

/// Classify ONE line of ffmpeg stderr (Task A). Pure + total — unit-tested WITHOUT a
/// spawn. Recognizes the machine-readable `-progress` keys (`out_time_us=` /
/// `out_time_ms=` / `out_time=` / `progress=`) and the human `Duration:` banner;
/// everything else is [`FfmpegLine::Ignore`].
///
/// Note: ffmpeg emits `out_time_us` and `out_time_ms` BOTH in microseconds (a
/// long-standing quirk — `out_time_ms` is a misnomer), so both are divided by 1000
/// to milliseconds; `out_time=` is a `HH:MM:SS.ffffff` timecode.
fn parse_ffmpeg_progress_line(line: &str) -> FfmpegLine {
    let t = line.trim();
    if let Some(v) = t.strip_prefix("out_time_us=") {
        return match v.trim().parse::<u64>() {
            Ok(us) => FfmpegLine::OutTime(us / 1000),
            Err(_) => FfmpegLine::Ignore,
        };
    }
    if let Some(v) = t.strip_prefix("out_time_ms=") {
        return match v.trim().parse::<u64>() {
            Ok(us) => FfmpegLine::OutTime(us / 1000),
            Err(_) => FfmpegLine::Ignore,
        };
    }
    if let Some(v) = t.strip_prefix("out_time=") {
        return match parse_hms_ms(v.trim()) {
            Some(ms) => FfmpegLine::OutTime(ms),
            None => FfmpegLine::Ignore,
        };
    }
    if t.starts_with("progress=") {
        return FfmpegLine::Tick; // continue | end — end of one progress block.
    }
    if let Some(ms) = parse_ffmpeg_duration_line(t) {
        return FfmpegLine::Duration(ms);
    }
    FfmpegLine::Ignore
}

/// Saturating completion percent (`0..=100`) from an elapsed `out_time_ms` and the
/// (optional) source total. `None` when the total is unknown or zero; an
/// `out_time` past the total saturates to 100. Pure + total.
fn ffmpeg_percent(out_time_ms: u64, total_ms: Option<u64>) -> Option<u8> {
    let total = total_ms?;
    if total == 0 {
        return None;
    }
    let pct = out_time_ms.saturating_mul(100) / total;
    Some(pct.min(100) as u8)
}

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
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
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

/// Fold one parsed stderr line into the running progress state (Task A): record the
/// source `Duration` once, advance the stall clock on each strictly-increasing
/// `out_time`, and emit an [`FfmpegProgress`] sample on each `progress=` tick. Keeps
/// the reader thread bounded (per-line, no accumulation) and coordinates with the
/// watchdog via `last_advance_ms` (an `AtomicU64` of `start.elapsed()` millis at the
/// last forward progress).
fn handle_progress_line<P: Fn(FfmpegProgress)>(
    line: &[u8],
    total_ms: &mut Option<u64>,
    max_out_ms: &mut u64,
    pending_out_ms: &mut u64,
    last_advance_ms: &AtomicU64,
    start: Instant,
    on_progress: &P,
) {
    let Ok(s) = std::str::from_utf8(line) else {
        return; // non-UTF-8 diagnostic bytes — never a progress line.
    };
    match parse_ffmpeg_progress_line(s) {
        FfmpegLine::Duration(ms) => {
            if total_ms.is_none() {
                *total_ms = Some(ms); // first (source) Duration wins.
            }
        }
        FfmpegLine::OutTime(ms) => {
            *pending_out_ms = ms;
            if ms > *max_out_ms {
                *max_out_ms = ms;
                // Forward progress ⇒ reset the stall clock (Task B).
                last_advance_ms.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
        }
        FfmpegLine::Tick => {
            on_progress(FfmpegProgress {
                percent: ffmpeg_percent(*pending_out_ms, *total_ms),
                out_time_ms: *pending_out_ms,
            });
        }
        FfmpegLine::Ignore => {}
    }
}

/// Drain a confined child's stderr `File` to EOF, retaining only the first `cap`
/// bytes (head-kept) but ALWAYS continuing to read past the cap so the child never
/// blocks on a full pipe (which would otherwise defeat the bounded-wait kill), while
/// ALSO parsing ffmpeg's `-progress` output **live, per line** (Task A): each
/// `progress=` tick invokes `on_progress`, and each forward `out_time` advance bumps
/// `last_advance_ms` for the watchdog's stall detection (Task B). Parsing is bounded
/// (a capped line buffer, discarded per line — no unbounded memory). A read error
/// ends the drain (the pipe broke = the child died). Returns the bounded tail.
fn read_stderr_with_progress<P: Fn(FfmpegProgress)>(
    mut f: std::fs::File,
    cap: usize,
    on_progress: P,
    last_advance_ms: &AtomicU64,
    start: Instant,
) -> Vec<u8> {
    use std::io::Read;
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut line: Vec<u8> = Vec::new();
    let mut total_ms: Option<u64> = None;
    let mut max_out_ms: u64 = 0;
    let mut pending_out_ms: u64 = 0;
    loop {
        match f.read(&mut tmp) {
            Ok(0) => break, // EOF — the child closed (or was killed and closed) stderr.
            Ok(n) => {
                let chunk = &tmp[..n];
                // Head-kept bounded tail (unchanged behavior).
                if out.len() < cap {
                    let take = n.min(cap - out.len());
                    out.extend_from_slice(&chunk[..take]);
                }
                // Per-line progress parse. ffmpeg's `-progress` uses '\n'; the banner
                // may use '\r' — treat either as a line terminator.
                for &b in chunk {
                    if b == b'\n' || b == b'\r' {
                        if !line.is_empty() {
                            handle_progress_line(
                                &line,
                                &mut total_ms,
                                &mut max_out_ms,
                                &mut pending_out_ms,
                                last_advance_ms,
                                start,
                                &on_progress,
                            );
                            line.clear();
                        }
                    } else if line.len() < MAX_PROGRESS_LINE_BYTES {
                        line.push(b);
                    }
                    // Beyond the cap the byte is dropped (bounded); the over-long line
                    // is discarded at the next terminator — it can't be a progress line.
                }
                // Beyond the tail cap: keep draining + discarding so the child can't block.
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
/// The run is bounded by a **progress-based stall watchdog** (Task B): the confined
/// child is force-killed only if its `-progress` `out_time` fails to advance for
/// `stall_timeout_ms`, so a legitimately-slow large transcode that keeps making
/// progress is NEVER wrongly killed — while `max_total_ms` is an absolute backstop
/// that terminates even a progress-spammer that keeps advancing forever. `on_progress`
/// (Task A) is invoked live per progress tick with a sanitized [`FfmpegProgress`]
/// (percent + elapsed ms only — no stderr text / paths cross). `cancel` (Task C) is
/// polled throughout: when set, the child is terminated and `cancelled = true` is
/// returned (a DISTINCT, benign outcome) — and the RAII path grants are revoked on
/// that path exactly as on every other.
///
/// Returns ffmpeg's exit code + the bounded stderr tail + the `cancelled` flag. The
/// CALLER (Phase 3) then reads the output file from the granted dir.
// The confined ffmpeg spawn genuinely needs each of these distinct inputs (program,
// argv, path grants, memory cap, the two watchdog bounds, the progress sink, the
// cancel flag); grouping them into a struct would only obscure the one call site.
#[allow(clippy::too_many_arguments)]
pub fn spawn_confined_exe<P: Fn(FfmpegProgress) + Send>(
    program: &Path,
    args: &[OsString],
    grants: &[(&Path, GrantAccess)],
    memory_cap_bytes: u64,
    stall_timeout_ms: u32,
    max_total_ms: u32,
    on_progress: P,
    cancel: &AtomicBool,
) -> Result<ConfinedExeOutput, SpawnError> {
    // Apply the scoped path grants up front; the RAII guards are held for the whole
    // spawn and revoked when `grant_guards` drops (success, cancel, stall/backstop
    // kill, any early `?`, or a panic).
    let mut grant_guards: Vec<PathGrant> = Vec::with_capacity(grants.len());
    for (path, access) in grants {
        grant_guards.push(grant_path_to_appcontainer(path, *access)?);
    }

    let ConfinedExeChild {
        guard,
        parent_stderr_read,
    } = setup_confined_exe_child(program, args, memory_cap_bytes)?;

    // SAFETY: we own `parent_stderr_read`; the `File` takes ownership and closes it
    // exactly once (when the reader thread drops it).
    let stderr_file = unsafe { std::fs::File::from_raw_handle(parent_stderr_read as _) };
    let start = Instant::now();
    // Shared stall clock: the reader bumps it on each forward `out_time`; the watchdog
    // reads it. A scoped thread borrows it + `on_progress` without `Arc`/`'static`.
    let last_advance = AtomicU64::new(0);
    // Capture a shared `&AtomicU64` (which is `Copy`) into the `move` reader closure so
    // the `AtomicU64` itself is NOT moved — the watchdog on this thread keeps its own
    // `&last_advance`. Both borrows are immutable + `AtomicU64: Sync`, and the scope
    // guarantees they outlive the reader thread.
    let last_advance_ref = &last_advance;

    let (exit_code, cancelled, stderr_tail) = std::thread::scope(|s| {
        // Drain + live-parse stderr on a scoped reader thread so a verbose ffmpeg can't
        // block on a full pipe, while the watchdog runs on this thread.
        let reader = s.spawn(move || {
            read_stderr_with_progress(
                stderr_file,
                FFMPEG_STDERR_CAP_BYTES,
                on_progress,
                last_advance_ref,
                start,
            )
        });
        // `guard` RAII-owns the Job + child until this disarms it: the cancellable,
        // stall-aware watchdog wait + kill, the exit code, and the handle teardown.
        // Once it returns, the child is dead → its stderr write end is closed → the
        // reader hits EOF and the join completes.
        let (code, cancelled) = finish_confined_watchdog(
            guard,
            &last_advance,
            start,
            stall_timeout_ms,
            max_total_ms,
            cancel,
        );
        let tail = reader.join().unwrap_or_default();
        (code, cancelled, tail)
    });

    Ok(ConfinedExeOutput {
        exit_code,
        stderr_tail,
        cancelled,
    })
    // `grant_guards` drops here → every path grant is revoked (DACL + label restored).
}

#[cfg(test)]
mod progress_tests {
    //! Pure ffmpeg progress/Duration parser tests (Task A) — NO spawn: the parsing
    //! + percent logic is exercised directly on synthetic stderr lines.
    use super::*;

    #[test]
    fn parses_duration_banner() {
        assert_eq!(
            parse_ffmpeg_duration_line("  Duration: 00:00:03.00, start: 0.000000, bitrate: 1 kb/s"),
            Some(3_000)
        );
        assert_eq!(
            parse_ffmpeg_duration_line("  Duration: 01:02:03.45,"),
            Some(((60 + 2) * 60 + 3) * 1000 + 450)
        );
        // No / unknown duration → None.
        assert_eq!(parse_ffmpeg_duration_line("  Duration: N/A, bitrate: N/A"), None);
        assert_eq!(parse_ffmpeg_duration_line("frame= 10 fps=5"), None);
    }

    #[test]
    fn classifies_progress_lines() {
        // out_time_us / out_time_ms are microseconds → milliseconds.
        assert_eq!(parse_ffmpeg_progress_line("out_time_us=1500000"), FfmpegLine::OutTime(1500));
        assert_eq!(parse_ffmpeg_progress_line("out_time_ms=2000000"), FfmpegLine::OutTime(2000));
        // out_time= is a timecode.
        assert_eq!(parse_ffmpeg_progress_line("out_time=00:00:01.250000"), FfmpegLine::OutTime(1250));
        // progress=continue|end → a tick.
        assert_eq!(parse_ffmpeg_progress_line("progress=continue"), FfmpegLine::Tick);
        assert_eq!(parse_ffmpeg_progress_line("progress=end"), FfmpegLine::Tick);
        // Malformed values are ignored (never panic, never a bogus sample).
        assert_eq!(parse_ffmpeg_progress_line("out_time_us=not-a-number"), FfmpegLine::Ignore);
        assert_eq!(parse_ffmpeg_progress_line("bitrate=N/A"), FfmpegLine::Ignore);
        assert_eq!(parse_ffmpeg_progress_line(""), FfmpegLine::Ignore);
    }

    #[test]
    fn percent_is_saturating_and_optional() {
        // Unknown duration → None.
        assert_eq!(ffmpeg_percent(1_000, None), None);
        assert_eq!(ffmpeg_percent(1_000, Some(0)), None);
        // Half-way.
        assert_eq!(ffmpeg_percent(1_500, Some(3_000)), Some(50));
        // Zero elapsed → 0.
        assert_eq!(ffmpeg_percent(0, Some(3_000)), Some(0));
        // out_time past duration saturates to 100 (never overflows u8).
        assert_eq!(ffmpeg_percent(9_999, Some(3_000)), Some(100));
        // No multiply overflow for a huge out_time.
        assert_eq!(ffmpeg_percent(u64::MAX, Some(1_000)), Some(100));
    }

    #[test]
    fn hms_parser_rejects_malformed() {
        assert_eq!(parse_hms_ms("00:00:01.5"), Some(1_500));
        assert_eq!(parse_hms_ms("00:00:01"), Some(1_000));
        assert_eq!(parse_hms_ms("1:2:3.004"), Some((3600 + 2 * 60 + 3) * 1000 + 4));
        assert_eq!(parse_hms_ms("00:99:00"), None); // minutes out of range
        assert_eq!(parse_hms_ms("00:00:99"), None); // seconds out of range
        assert_eq!(parse_hms_ms("garbage"), None);
        assert_eq!(parse_hms_ms("1:2:3:4"), None); // too many fields
    }

    #[test]
    fn reader_state_advances_clock_and_emits_on_tick() {
        // Drive the fold directly (no spawn): a Duration then an advancing out_time +
        // tick must emit the right percent and bump the stall clock. Seed the clock
        // with a sentinel so the assert proves the store EXECUTED regardless of timing
        // (`start.elapsed()` can legitimately be 0 ms on a fast machine).
        let last = AtomicU64::new(u64::MAX);
        let start = Instant::now();
        let mut total = None;
        let mut max_out = 0u64;
        let mut pending = 0u64;
        // Interior mutability so the sink is `Fn` (the parser takes `&P: Fn`).
        let samples: std::cell::RefCell<Vec<FfmpegProgress>> = std::cell::RefCell::new(Vec::new());
        let sink = |p: FfmpegProgress| samples.borrow_mut().push(p);
        for l in [
            b"  Duration: 00:00:02.00,".as_slice(),
            b"out_time_us=1000000".as_slice(),
            b"progress=continue".as_slice(),
        ] {
            handle_progress_line(l, &mut total, &mut max_out, &mut pending, &last, start, &sink);
        }
        assert_eq!(total, Some(2_000));
        assert_eq!(
            samples.into_inner(),
            vec![FfmpegProgress { percent: Some(50), out_time_ms: 1_000 }]
        );
        assert_ne!(
            last.load(Ordering::Relaxed),
            u64::MAX,
            "forward progress bumped the stall clock"
        );
    }
}
