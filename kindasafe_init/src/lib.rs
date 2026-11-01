use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

#[derive(Debug, PartialEq, Clone)]
pub enum InitError {
    InstallSignalHandlersFailed,
    UnsupportedPreviousHandler,
    SanityCheckFailed,
}

// Publish the previous disposition before installing crash_handler, so even a
// signal delivered inside sigaction sees the fallback. The handler is stored
// last with Release ordering, so a reader that sees it also sees its flags.
struct Fallback {
    handler: AtomicUsize,
    flags: AtomicI32,
}

impl Fallback {
    const fn new() -> Self {
        Self {
            handler: AtomicUsize::new(libc::SIG_DFL),
            flags: AtomicI32::new(0),
        }
    }

    fn store(&self, action: &libc::sigaction) {
        self.flags.store(action.sa_flags, Ordering::Relaxed);
        self.handler.store(action.sa_sigaction, Ordering::Release);
    }
}

static FALLBACK_SIGSEGV: Fallback = Fallback::new();
static FALLBACK_SIGBUS: Fallback = Fallback::new();

// TODO: Handle fork safety for this lock, the cached result, and inherited
// handlers/fallbacks together. Resetting the lock and reinstalling could save
// crash_handler as its own fallback. See https://github.com/grafana/pyroscope-kinda-safe/issues/57.
static INIT_LOCK: Mutex<Option<Result<(), InitError>>> = Mutex::new(None);

pub fn is_initialized() -> Option<Result<(), InitError>> {
    let g = INIT_LOCK.lock().expect("initialization lock poisoned");
    g.clone()
}
/// Install the handlers once, preserving the previous handlers as fallbacks.
///
/// Calls to this function are serialized. The installed handlers inherit the
/// flags of the previous handlers, such as `SA_ONSTACK` and `SA_NODEFER`.
///
/// # Errors
/// Returns `UnsupportedPreviousHandler` and changes nothing if a previous
/// SIGSEGV or SIGBUS handler was installed with `SA_RESETHAND`, or on macOS
/// is `SIG_IGN`.
///
/// # Safety
/// The caller must coordinate installation with other code that changes SIGSEGV
/// or SIGBUS dispositions: querying the old disposition and installing the new
/// one are separate syscalls.
///
/// Previous handlers must support direct chaining and remain valid for as long
/// as our handlers can call them. SIG_DFL and SIG_IGN are honored
/// without calling anything.
pub unsafe fn init() -> Result<(), InitError> {
    let mut g = INIT_LOCK.lock().expect("initialization lock poisoned");
    if let Some(prev) = g.clone() {
        return prev;
    }

    let res = init_locked();
    *g = Some(res.clone());
    res
}

// Called only while holding INIT_LOCK, and never retried, even after a partial
// installation failure. A published fallback is therefore never overwritten.
fn init_locked() -> Result<(), InitError> {
    let old_segv =
        previous_handler(libc::SIGSEGV).map_err(|_| InitError::InstallSignalHandlersFailed)?;
    let old_bus =
        previous_handler(libc::SIGBUS).map_err(|_| InitError::InstallSignalHandlersFailed)?;
    // The kernel resets a SA_RESETHAND handler to SIG_DFL when it first runs.
    // Inherited, the flag would uninstall crash_handler after the first fault.
    if (old_segv.sa_flags | old_bus.sa_flags) & libc::SA_RESETHAND != 0 {
        return Err(InitError::UnsupportedPreviousHandler);
    }
    // SIG_IGN drops a sent signal but must not drop a fault, and macOS si_code
    // does not tell the two apart. See call_fallback.
    if cfg!(target_os = "macos")
        && (old_segv.sa_sigaction == libc::SIG_IGN || old_bus.sa_sigaction == libc::SIG_IGN)
    {
        return Err(InitError::UnsupportedPreviousHandler);
    }
    install(libc::SIGSEGV, &old_segv, crash_handler, &FALLBACK_SIGSEGV)
        .map_err(|_| InitError::InstallSignalHandlersFailed)?;
    install(libc::SIGBUS, &old_bus, crash_handler, &FALLBACK_SIGBUS)
        .map_err(|_| InitError::InstallSignalHandlersFailed)?;
    Ok(())
}

/// # Safety
/// `data` must be a valid pointer to `libc::ucontext_t`.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
unsafe extern "C" fn crash_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    data: *mut libc::c_void,
) {
    unsafe {
        let ctx: *mut libc::ucontext_t = data as *mut libc::ucontext_t;
        let pc = (*ctx).uc_mcontext.gregs[libc::REG_RIP as usize] as usize;
        for x in kindasafe::crash_points().crash_points {
            if x.pc == pc {
                (*ctx).uc_mcontext.gregs[libc::REG_RIP as usize] = (pc + x.skip) as libc::greg_t;
                let reg_idx = match x.signal_reg {
                    kindasafe::Reg::Rax => libc::REG_RAX as usize,
                    kindasafe::Reg::Rdx => libc::REG_RDX as usize,
                };
                (*ctx).uc_mcontext.gregs[reg_idx] = sig as u64 as libc::greg_t;
                return;
            }
        }
        fallback(sig, info, data);
    }
}

/// # Safety
/// `data` must be a valid pointer to `libc::ucontext_t`.
#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
unsafe extern "C" fn crash_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    data: *mut libc::c_void,
) {
    unsafe {
        let ctx: *mut libc::ucontext_t = data as *mut libc::ucontext_t;
        let mctx = (*ctx).uc_mcontext;
        let ss = &mut (*mctx).__ss;
        let pc = ss.__rip as usize;
        for x in kindasafe::crash_points().crash_points {
            if x.pc == pc {
                ss.__rip = (pc + x.skip) as u64;
                match x.signal_reg {
                    kindasafe::Reg::Rax => ss.__rax = sig as u64,
                    kindasafe::Reg::Rdx => ss.__rdx = sig as u64,
                };
                return;
            }
        }
        fallback(sig, info, data);
    }
}

/// # Safety
/// `data` must be a valid pointer to `libc::ucontext_t`.
#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
unsafe extern "C" fn crash_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    data: *mut libc::c_void,
) {
    unsafe {
        let ctx: *mut libc::ucontext_t = data as *mut libc::ucontext_t;
        let pc = (*ctx).uc_mcontext.pc as usize;
        for x in kindasafe::crash_points().crash_points {
            if x.pc == pc {
                (*ctx).uc_mcontext.pc = (pc + x.skip) as u64;
                // libc provides no named constants for aarch64 register indices;
                // mcontext_t.regs is [u64; 31] where index matches register number.
                let reg_idx = match x.signal_reg {
                    kindasafe::Reg::X0 => 0,
                    kindasafe::Reg::X1 => 1,
                };
                (*ctx).uc_mcontext.regs[reg_idx] = sig as u64;
                return;
            }
        }
        fallback(sig, info, data);
    }
}

/// # Safety
/// `data` must be a valid pointer to `libc::ucontext_t`.
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
unsafe extern "C" fn crash_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    data: *mut libc::c_void,
) {
    unsafe {
        let ctx: *mut libc::ucontext_t = data as *mut libc::ucontext_t;
        let mctx = (*ctx).uc_mcontext;
        let pc = (*mctx).__ss.__pc as usize;
        for x in kindasafe::crash_points().crash_points {
            if x.pc == pc {
                (*mctx).__ss.__pc = (pc + x.skip) as u64;
                // libc provides no named constants for aarch64 register indices;
                // __darwin_arm_thread_state64.__x is [u64; 29] where index matches register number.
                let reg_idx = match x.signal_reg {
                    kindasafe::Reg::X0 => 0,
                    kindasafe::Reg::X1 => 1,
                };
                (*mctx).__ss.__x[reg_idx] = sig as u64;
                return;
            }
        }
        fallback(sig, info, data);
    }
}

// Dispatch to the handler that was active before init().
//
// SIG_IGN and SIG_DFL are sentinels, not code. A signal sent by a process
// (si_code <= 0) does not recur when the handler returns, so an ignored one is
// dropped and a default one is re-raised while the signal is still blocked:
// it is delivered with the default action as soon as this handler returns. A
// hardware fault recurs on return, so restoring SIG_DFL and returning delivers
// the default action with the original siginfo. Linux does the same for a
// fault whose signal is ignored.
//
// On macOS, si_code does not show whether a SIGSEGV or SIGBUS was sent or
// caused by a fault: the kernel sets it without regard to the signal's origin.
// A sent signal mistaken for a fault would be lost, so the signal is always
// re-raised there, which delivers the default action for a fault as well.
// SIG_IGN cannot be honored without knowing the origin, so init() rejects it
// on macOS.
fn call_fallback(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    data: *mut libc::c_void,
    fallback: &Fallback,
) {
    let handler = fallback.handler.load(Ordering::Acquire);
    let flags = fallback.flags.load(Ordering::Relaxed);
    let sent_by_process = unsafe { (*info).si_code } <= 0;
    match handler {
        libc::SIG_IGN if sent_by_process => {}
        libc::SIG_IGN | libc::SIG_DFL => {
            restore_default_ignal_handler(sig);
            if sent_by_process || cfg!(target_os = "macos") {
                unsafe { libc::raise(sig) };
            }
        }
        _ if flags & libc::SA_SIGINFO != 0 => {
            let handler = unsafe {
                std::mem::transmute::<
                    usize,
                    extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
                >(handler)
            };
            handler(sig, info, data);
        }
        _ => {
            let handler =
                unsafe { std::mem::transmute::<usize, extern "C" fn(libc::c_int)>(handler) };
            handler(sig);
        }
    }
}

unsafe fn fallback(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void) {
    if sig == libc::SIGSEGV {
        call_fallback(sig, info, data, &FALLBACK_SIGSEGV);
        return;
    }
    if sig == libc::SIGBUS {
        call_fallback(sig, info, data, &FALLBACK_SIGBUS);
    }
}

fn previous_handler(signal: libc::c_int) -> Result<libc::sigaction, ()> {
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, std::ptr::null_mut(), &mut old) != 0 {
            return Err(());
        }
        Ok(old)
    }
}

fn install(
    signal: libc::c_int,
    old: &libc::sigaction,
    handler: unsafe extern "C" fn(
        sig: libc::c_int,
        info: *mut libc::siginfo_t,
        data: *mut libc::c_void,
    ),
    fallback: &Fallback,
) -> Result<(), ()> {
    unsafe {
        let mut new: libc::sigaction = *old;
        new.sa_sigaction = handler as usize;
        new.sa_flags |= libc::SA_RESTART | libc::SA_SIGINFO;
        fallback.store(old);
        if libc::sigaction(signal, &new, std::ptr::null_mut()) != 0 {
            return Err(());
        }
        Ok(())
    }
}

pub fn restore_default_ignal_handler(sig: libc::c_int) {
    let action: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) };
}

/// Sanity check that kindasafe crash recovery is working.
///
/// Maps a PROT_NONE page, attempts to read it via `kindasafe::u64`,
/// and verifies the read returns an error (SIGSEGV) instead of crashing.
/// Unmaps the page before returning.
///
/// Returns `Ok(())` if the sanity check passes, `Err(SanityCheckFailed)` if
/// the read unexpectedly succeeded (meaning crash recovery is broken).
pub fn sanity_check() -> Result<(), InitError> {
    unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            return Err(InitError::SanityCheckFailed);
        }
        let addr = page as u64;
        let result = kindasafe::u64(addr);
        libc::munmap(page, 4096);
        match result {
            Err(_) => Ok(()),
            Ok(_) => Err(InitError::SanityCheckFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_idempotent() {
        // SAFETY: These tests only change signal dispositions through init().
        assert!(unsafe { init() }.is_ok());
        assert!(unsafe { init() }.is_ok());
        assert!(is_initialized().is_some());
        assert_eq!(is_initialized(), Some(Ok(())));
    }

    #[test]
    fn test_sanity_check() {
        // SAFETY: These tests only change signal dispositions through init().
        assert!(unsafe { init() }.is_ok());
        assert!(sanity_check().is_ok());
    }
}
