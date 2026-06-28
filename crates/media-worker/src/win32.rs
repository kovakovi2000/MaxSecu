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

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, STARTUPINFOW,
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

/// Spawn the `media-worker` binary at `worker_path` with `extra_args`, confined to
/// an AppContainer (no network/key access) + a Job Object (no child processes,
/// memory-capped, kill-on-close). `stdin_data` is written to the worker's stdin;
/// its stdout is captured.
pub fn spawn_confined(
    worker_path: &Path,
    extra_args: &[&str],
    stdin_data: &[u8],
    memory_cap_bytes: u64,
) -> Result<ConfinedOutput, SpawnError> {
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
    si.StartupInfo.hStdError = child_stdout;
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

    // Job Object: one process only (no children), memory-capped, kill-on-close.
    let run = (|| -> Result<ConfinedOutput, SpawnError> {
        let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if job.is_null() {
            return Err(SpawnError::last("CreateJobObject"));
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
            return Err(e);
        }
        if unsafe { AssignProcessToJobObject(job, pi.hProcess) } == 0 {
            let e = SpawnError::last("AssignProcessToJobObject");
            unsafe { CloseHandle(job) };
            return Err(e);
        }
        // Now that confinement is in place, let the worker run.
        unsafe { ResumeThread(pi.hThread) };

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

        unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };
        let mut code: u32 = 0;
        unsafe { GetExitCodeProcess(pi.hProcess, &mut code) };
        // Closing the job (kill-on-close) after the process already exited is a
        // no-op for it but releases the job.
        unsafe { CloseHandle(job) };
        Ok(ConfinedOutput {
            exit_code: code,
            stdout: out,
        })
    })();

    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    run
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
