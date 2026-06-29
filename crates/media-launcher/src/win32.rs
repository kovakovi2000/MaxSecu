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
    WAIT_TIMEOUT,
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
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
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
    let (job, pi) = guard.disarm();
    // SAFETY: `pi.hProcess` is the live confined child; wait up to the bound, then
    // — on timeout — actively kill it so a spinning worker can't hang the launcher.
    unsafe {
        if WaitForSingleObject(pi.hProcess, WORKER_WAIT_TIMEOUT_MS) == WAIT_TIMEOUT {
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
