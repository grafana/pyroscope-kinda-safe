use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, PartialEq, Clone)]
pub enum InitError {
    InstallSignalHandlersFailed,
    SanityCheckFailed,
}

// Only the handler address is used when chaining. Publish it before installing
// crash_handler, so even a signal delivered inside sigaction sees the fallback.
static FALLBACK_SIGSEGV: AtomicUsize = AtomicUsize::new(libc::SIG_DFL);
static FALLBACK_SIGBUS: AtomicUsize = AtomicUsize::new(libc::SIG_DFL);

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
/// Calls to this function are serialized.
///
/// # Safety
/// The caller must coordinate installation with other code that changes SIGSEGV
/// or SIGBUS dispositions: querying the old disposition and installing the new
/// one are separate syscalls.
///
/// Previous dispositions must be SIG_DFL or SA_SIGINFO handlers that support
/// direct chaining and remain valid for as long as our handlers can call them.
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
    new_signal_handler(libc::SIGSEGV, crash_handler, &FALLBACK_SIGSEGV)
        .map_err(|_| InitError::InstallSignalHandlersFailed)?;
    new_signal_handler(libc::SIGBUS, crash_handler, &FALLBACK_SIGBUS)
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

fn call_fallback(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    data: *mut libc::c_void,
    fallback: usize,
) {
    if fallback == libc::SIG_DFL {
        restore_default_ignal_handler(sig);
    } else {
        let handler = unsafe {
            std::mem::transmute::<
                usize,
                extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
            >(fallback)
        };
        handler(sig, info, data);
    }
}
unsafe fn fallback(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void) {
    if sig == libc::SIGSEGV {
        call_fallback(sig, info, data, FALLBACK_SIGSEGV.load(Ordering::Acquire));
        return;
    }
    if sig == libc::SIGBUS {
        call_fallback(sig, info, data, FALLBACK_SIGBUS.load(Ordering::Acquire));
    }
}

fn new_signal_handler(
    signal: libc::c_int,
    handler: unsafe extern "C" fn(
        sig: libc::c_int,
        info: *mut libc::siginfo_t,
        data: *mut libc::c_void,
    ),
    fallback: &AtomicUsize,
) -> Result<(), ()> {
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, std::ptr::null_mut(), &mut old) != 0 {
            return Err(());
        }
        let mut new: libc::sigaction = old;
        new.sa_sigaction = handler as usize;
        new.sa_flags |= libc::SA_RESTART | libc::SA_SIGINFO;
        fallback.store(old.sa_sigaction, Ordering::Release);
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
