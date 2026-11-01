//! Signal-handler initialization for `kindasafe`.
//!
//! Fallback dispositions are published atomically *before* the corresponding
//! crash handler is installed, so a signal delivered as soon as the handler
//! becomes reachable can never observe an unpublished (zeroed) fallback.
//!
//! POSIX `sigaction` has no atomic query-and-install operation. We therefore
//! assume that other threads do not concurrently change the SIGSEGV/SIGBUS
//! disposition while [`init`] is running. If they do, the pre-install snapshot
//! is refreshed with the disposition actually replaced as soon as installation
//! returns; a signal in that short interval can observe the pre-install
//! snapshot instead of the concurrent third-party action.

use std::sync::atomic::{AtomicPtr, Ordering};

#[derive(Debug, PartialEq, Clone)]
pub enum InitError {
    InstallSignalHandlersFailed,
    SanityCheckFailed,
}

struct FallbackAction(libc::sigaction);

// These point at immutable `FallbackAction`s. Published actions are leaked for
// the lifetime of the process because a signal handler may still be reading an
// action while a later publication replaces the pointer.
static FALLBACK_SIGSEGV: AtomicPtr<FallbackAction> = AtomicPtr::new(std::ptr::null_mut());
static FALLBACK_SIGBUS: AtomicPtr<FallbackAction> = AtomicPtr::new(std::ptr::null_mut());

static INIT_LOCK: spin::Mutex<Option<Result<(), InitError>>> = spin::Mutex::new(None);

pub fn is_initialized() -> Option<Result<(), InitError>> {
    let g = INIT_LOCK.lock();
    g.clone()
}
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
    init_locked_with_hook(|_| {})
}

fn init_locked_with_hook<F>(mut after_install: F) -> Result<(), InitError>
where
    F: FnMut(libc::c_int),
{
    install_signal_handler(libc::SIGSEGV, crash_handler, &mut after_install)?;
    install_signal_handler(libc::SIGBUS, crash_handler, &mut after_install)?;
    Ok(())
}

fn install_signal_handler<F>(
    signal: libc::c_int,
    handler: unsafe fn(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void),
    after_install: &mut F,
) -> Result<(), InitError>
where
    F: FnMut(libc::c_int),
{
    let previous =
        query_signal_handler(signal).map_err(|_| InitError::InstallSignalHandlersFailed)?;

    // Publish before installation: once `sigaction` below returns (or even
    // while it is executing on another thread), the handler must find a valid
    // fallback. Under the no-concurrent-third-party assumption below, this is
    // the exact disposition that `sigaction` will replace.
    publish_fallback(signal, previous);

    let replaced = new_signal_handler(signal, handler, previous)
        .map_err(|_| InitError::InstallSignalHandlersFailed)?;

    // Test hook: let the regression test inject a signal after the handler is
    // reachable but before the post-install refresh below.
    after_install(signal);

    // If another thread changed the disposition between the query and our
    // install, publish the action the kernel actually replaced. The handler
    // already has the pre-install snapshot, so there is no unpublished window.
    publish_fallback(signal, replaced);
    Ok(())
}

fn fallback_slot(signal: libc::c_int) -> Option<&'static AtomicPtr<FallbackAction>> {
    match signal {
        libc::SIGSEGV => Some(&FALLBACK_SIGSEGV),
        libc::SIGBUS => Some(&FALLBACK_SIGBUS),
        _ => None,
    }
}

fn publish_fallback(signal: libc::c_int, action: libc::sigaction) {
    let Some(slot) = fallback_slot(signal) else {
        return;
    };
    let published = Box::into_raw(Box::new(FallbackAction(action)));
    let previous = slot.swap(published, Ordering::SeqCst);
    // Intentionally leak both `previous` and `published`: handlers never take a
    // lock, so an in-flight handler may still be dereferencing `previous`.
    let _ = previous;
}

unsafe fn load_fallback(signal: libc::c_int) -> Option<&'static FallbackAction> {
    let slot = fallback_slot(signal)?;
    let action = slot.load(Ordering::SeqCst);
    if action.is_null() {
        None
    } else {
        Some(unsafe { &*action })
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
    let Some(fallback) = (unsafe { load_fallback(sig) }) else {
        // Unreachable for handlers installed by this crate: publication happens
        // first. Keep the failure mode conservative if a foreign caller somehow
        // installs `crash_handler` directly.
        restore_default_ignal_handler(sig);
        return;
    };
    call_fallback(sig, info, data, fallback.0);
}

fn query_signal_handler(signal: libc::c_int) -> Result<libc::sigaction, ()> {
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, std::ptr::null_mut(), &mut old) != 0 {
            return Err(());
        }
        Ok(old)
    }
}

fn new_signal_handler(
    signal: libc::c_int,
    handler: unsafe fn(sig: libc::c_int, info: *mut libc::siginfo_t, data: *mut libc::c_void),
    previous: libc::sigaction,
) -> Result<libc::sigaction, ()> {
    unsafe {
        let mut new = previous;
        new.sa_sigaction = handler as usize;
        new.sa_flags |= libc::SA_RESTART | libc::SA_SIGINFO;
        let mut replaced: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(signal, &new, &mut replaced) != 0 {
            return Err(());
        }
        Ok(replaced)
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
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const BOUNDARY_CHILD_ENV: &str = "KINDASAFE_INSTALL_BOUNDARY_CHILD";
    static SIGSEGV_FALLBACKS: AtomicUsize = AtomicUsize::new(0);
    static SIGBUS_FALLBACKS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn counting_sigsegv_handler(
        _sig: libc::c_int,
        _info: *mut libc::siginfo_t,
        _data: *mut libc::c_void,
    ) {
        SIGSEGV_FALLBACKS.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn counting_sigbus_handler(
        _sig: libc::c_int,
        _info: *mut libc::siginfo_t,
        _data: *mut libc::c_void,
    ) {
        SIGBUS_FALLBACKS.fetch_add(1, Ordering::SeqCst);
    }

    fn install_counting_handler(
        signal: libc::c_int,
        handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
    ) {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as usize;
            action.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
            assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
            assert_eq!(
                libc::sigaction(signal, &action, std::ptr::null_mut()),
                0,
                "failed to install test handler"
            );
        }
    }

    fn run_installation_boundary_child() {
        install_counting_handler(libc::SIGSEGV, counting_sigsegv_handler);
        install_counting_handler(libc::SIGBUS, counting_sigbus_handler);

        init_locked_with_hook(|signal| {
            // Deliver synchronously at the earliest point where the newly
            // installed handler is reachable, before the post-install refresh.
            assert_eq!(unsafe { libc::raise(signal) }, 0);
        })
        .expect("init_locked_with_hook failed");

        assert_eq!(SIGSEGV_FALLBACKS.load(Ordering::SeqCst), 1);
        assert_eq!(SIGBUS_FALLBACKS.load(Ordering::SeqCst), 1);

        // The normal post-initialization path must still chain to the saved
        // application handlers as well.
        assert_eq!(unsafe { libc::raise(libc::SIGSEGV) }, 0);
        assert_eq!(unsafe { libc::raise(libc::SIGBUS) }, 0);
        assert_eq!(SIGSEGV_FALLBACKS.load(Ordering::SeqCst), 2);
        assert_eq!(SIGBUS_FALLBACKS.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_fallback_is_published_before_installation_boundary() {
        if std::env::var_os(BOUNDARY_CHILD_ENV).is_some() {
            run_installation_boundary_child();
            return;
        }

        // Run the boundary scenario in a fresh process so replacing the global
        // signal dispositions cannot interfere with other unit tests.
        let status = Command::new(std::env::current_exe().expect("current_exe failed"))
            .args([
                "--exact",
                "tests::test_fallback_is_published_before_installation_boundary",
                "--nocapture",
            ])
            .env(BOUNDARY_CHILD_ENV, "1")
            .status()
            .expect("failed to spawn boundary test child");
        assert!(status.success(), "installation-boundary child failed");
    }

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
