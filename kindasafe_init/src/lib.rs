#[derive(Debug, PartialEq, Clone)]
pub enum InitError {
    InstallSignalHandlersFailed,
    SanityCheckFailed,
}

/// Reason why fault recovery is not currently available on this thread.
///
/// This is returned by [`recovery_available`]. It is intended for sampling
/// integrations that need to decide whether a potentially-faulting
/// `kindasafe` read can be attempted safely.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecoveryUnavailable {
    /// [`init`] has not completed successfully yet.
    NotInitialized,
    /// [`init`] ran but failed to install the recovery handlers.
    InitializationFailed,
    /// The signal's current disposition is not kindasafe's recovery handler.
    ///
    /// This usually means another component replaced the handler after
    /// initialization.
    HandlerNotInstalled(libc::c_int),
    /// The signal is blocked on the calling thread.
    ///
    /// A synchronous fault for a blocked signal cannot be recovered by the
    /// handler; on Linux the process is typically terminated instead.
    SignalBlocked(libc::c_int),
}

// todo think how to have less static mut
static mut FALLBACK_SIGSEGV: libc::sigaction = unsafe { std::mem::zeroed() };
static mut FALLBACK_SIGBUS: libc::sigaction = unsafe { std::mem::zeroed() };

static INIT_LOCK: spin::Mutex<Option<Result<(), InitError>>> = spin::Mutex::new(None);

// Lock-free initialization state for `recovery_available`, which must be safe
// to call from a signal handler. 0 = not initialized, 1 = ready, 2 = failed.
const INIT_STATE_NOT_READY: u8 = 0;
const INIT_STATE_READY: u8 = 1;
const INIT_STATE_FAILED: u8 = 2;
static INIT_STATE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(INIT_STATE_NOT_READY);

pub fn is_initialized() -> Option<Result<(), InitError>> {
    let g = INIT_LOCK.lock();
    g.clone()
}

/// Installs the process-wide SIGSEGV and SIGBUS recovery handlers.
///
/// This function is idempotent and remembers the result of the first call. It
/// does not change the calling thread's signal mask. After it succeeds, call
/// [`recovery_available`] before performing a `kindasafe` read whenever the
/// current thread might have SIGSEGV or SIGBUS blocked.
pub fn init() -> Result<(), InitError> {
    let mut g = INIT_LOCK.lock();
    if let Some(prev) = g.clone() {
        return prev;
    }

    let res = init_locked();
    *g = Some(res.clone());
    res
}

pub fn init_locked() -> Result<(), InitError> {
    unsafe {
        FALLBACK_SIGSEGV = match new_signal_handler(libc::SIGSEGV, crash_handler) {
            Ok(old) => old,
            Err(()) => {
                INIT_STATE.store(INIT_STATE_FAILED, std::sync::atomic::Ordering::Release);
                return Err(InitError::InstallSignalHandlersFailed);
            }
        };
        FALLBACK_SIGBUS = match new_signal_handler(libc::SIGBUS, crash_handler) {
            Ok(old) => old,
            Err(()) => {
                INIT_STATE.store(INIT_STATE_FAILED, std::sync::atomic::Ordering::Release);
                return Err(InitError::InstallSignalHandlersFailed);
            }
        };
    }
    INIT_STATE.store(INIT_STATE_READY, std::sync::atomic::Ordering::Release);
    Ok(())
}

/// Checks whether a fault in a `kindasafe` read can be recovered on the
/// calling thread at this moment.
///
/// Unlike [`is_initialized`], this also verifies that SIGSEGV and SIGBUS still
/// point at kindasafe's recovery handlers and that neither signal is blocked on
/// the current thread. It never changes any signal handler or mask, so it is
/// safe to use from profiling signal callbacks. It is lock-free after
/// initialization and deliberately does not inspect the interrupted
/// `ucontext_t`: a nested signal handler inherits the interrupted thread's
/// signal mask, which is the mask checked here.
///
/// A successful return does not make a later read safe by itself. Another
/// thread can replace a handler, and code can change the mask between this
/// check and the read. Integrations should therefore call this at the boundary
/// of each sample (ideally first in the signal handler) and skip the read on
/// any error. In particular, do not clear SIGSEGV/SIGBUS from an application's
/// signal mask from inside a profiling handler.
pub fn recovery_available() -> Result<(), RecoveryUnavailable> {
    use std::sync::atomic::Ordering;

    match INIT_STATE.load(Ordering::Acquire) {
        INIT_STATE_READY => {}
        INIT_STATE_FAILED => return Err(RecoveryUnavailable::InitializationFailed),
        _ => return Err(RecoveryUnavailable::NotInitialized),
    }

    for signal in [libc::SIGSEGV, libc::SIGBUS] {
        if !handler_is_installed(signal) {
            return Err(RecoveryUnavailable::HandlerNotInstalled(signal));
        }
    }

    for signal in [libc::SIGSEGV, libc::SIGBUS] {
        match signal_is_blocked(signal) {
            Ok(false) => {}
            // Treat an inspection failure as blocked: attempting the read
            // could terminate the process, so failing closed is the only safe
            // option.
            Ok(true) | Err(()) => return Err(RecoveryUnavailable::SignalBlocked(signal)),
        }
    }

    Ok(())
}

fn handler_is_installed(signal: libc::c_int) -> bool {
    unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, std::ptr::null(), &mut current) != 0 {
            return false;
        }
        current.sa_sigaction == crash_handler as *const () as usize
    }
}

fn signal_is_blocked(signal: libc::c_int) -> Result<bool, ()> {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        if libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut set) != 0 {
            return Err(());
        }
        match libc::sigismember(&set, signal) {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(()),
        }
    }
}

/// # Safety
/// `data` must be a valid pointer to `libc::ucontext_t`.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
unsafe fn crash_handler(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void) {
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
unsafe fn crash_handler(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void) {
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
unsafe fn crash_handler(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void) {
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
unsafe fn crash_handler(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void) {
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

fn call_fallback(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    data: *mut libc::c_void,
    fallback: libc::sigaction,
) {
    if fallback.sa_sigaction == 0 {
        restore_default_ignal_handler(sig);
    } else {
        let handler = unsafe {
            std::mem::transmute::<
                usize,
                extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
            >(fallback.sa_sigaction)
        };
        handler(sig, info, data);
    }
}
unsafe fn fallback(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void) {
    if sig == libc::SIGSEGV {
        call_fallback(sig, info, data, unsafe { FALLBACK_SIGSEGV });
        return;
    }
    if sig == libc::SIGBUS {
        call_fallback(sig, info, data, unsafe { FALLBACK_SIGBUS });
    }
}

fn new_signal_handler(
    signal: libc::c_int,
    handler: unsafe fn(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void),
) -> Result<libc::sigaction, ()> {
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, std::ptr::null_mut(), &mut old) != 0 {
            return Err(());
        }
        let mut new: libc::sigaction = old;
        new.sa_sigaction = handler as usize;
        new.sa_flags |= libc::SA_RESTART | libc::SA_SIGINFO;
        if libc::sigaction(signal, &new, &mut old) != 0 {
            return Err(());
        }
        Ok(old)
    }
}

pub fn restore_default_ignal_handler(sig: libc::c_int) {
    let action: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) };
}

/// Sanity check that kindasafe crash recovery is working on this thread.
///
/// First checks [`recovery_available`]. If recovery is not currently possible
/// (for example because SIGSEGV/SIGBUS is blocked), returns
/// `Err(SanityCheckFailed)` without attempting a fault. Otherwise maps a
/// PROT_NONE page, attempts to read it via `kindasafe::u64`, and verifies the
/// read returns an error (SIGSEGV/SIGBUS) instead of crashing. Unmaps the page
/// before returning.
///
/// Returns `Ok(())` if the sanity check passes, `Err(SanityCheckFailed)` if
/// recovery is unavailable or the read unexpectedly succeeded (meaning crash
/// recovery is broken).
pub fn sanity_check() -> Result<(), InitError> {
    if recovery_available().is_err() {
        return Err(InitError::SanityCheckFailed);
    }
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
        assert!(init().is_ok());
        assert!(init().is_ok());
        assert!(is_initialized().is_some());
        assert_eq!(is_initialized(), Some(Ok(())));
    }

    #[test]
    fn test_sanity_check() {
        assert!(init().is_ok());
        assert!(sanity_check().is_ok());
    }
}
