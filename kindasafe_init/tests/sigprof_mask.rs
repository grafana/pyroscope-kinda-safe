// Each integration test binary has its own signal handlers and init state.
// Check both installed masks and the mask seen by a directly chained handler.

use std::sync::atomic::{AtomicI32, Ordering};

#[path = "common/errno_guard.rs"]
mod errno_guard;
use errno_guard::ErrnoGuard;

static SEGV_MASK: AtomicI32 = AtomicI32::new(-1);
static BUS_MASK: AtomicI32 = AtomicI32::new(-1);

extern "C" fn previous_handler(
    signal: libc::c_int,
    _info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    let _errno_guard = ErrnoGuard::new();
    let (inherited, other, result) = match signal {
        libc::SIGSEGV => (libc::SIGUSR1, libc::SIGUSR2, &SEGV_MASK),
        libc::SIGBUS => (libc::SIGUSR2, libc::SIGUSR1, &BUS_MASK),
        _ => return,
    };
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) } != 0 {
        result.store(-2, Ordering::Relaxed);
        return;
    }
    let bits = unsafe {
        libc::sigismember(&mask, libc::SIGPROF)
            | (libc::sigismember(&mask, inherited) << 1)
            | (libc::sigismember(&mask, other) << 2)
            | (libc::sigismember(&mask, signal) << 3)
            | (libc::sigismember(&mask, libc::SIGWINCH) << 4)
    };
    result.store(bits, Ordering::Relaxed);
}

fn current_thread_mask() -> libc::sigset_t {
    unsafe {
        let mut mask = std::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
            0
        );
        mask
    }
}

fn assert_mask_member(mask: &libc::sigset_t, signal: libc::c_int, expected: libc::c_int) {
    assert_eq!(unsafe { libc::sigismember(mask, signal) }, expected);
}

fn assert_thread_mask_restored() {
    let mask = current_thread_mask();
    for signal in [
        libc::SIGPROF,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGSEGV,
        libc::SIGBUS,
    ] {
        assert_mask_member(&mask, signal, 0);
    }
    assert_mask_member(&mask, libc::SIGWINCH, 1);
}

#[test]
fn sigprof_is_blocked_during_recovery_and_chained_handlers() {
    let _errno_guard = ErrnoGuard::new();
    unsafe {
        for (signal, inherited) in [
            (libc::SIGSEGV, libc::SIGUSR1),
            (libc::SIGBUS, libc::SIGUSR2),
        ] {
            let mut old: libc::sigaction = std::mem::zeroed();
            old.sa_sigaction = previous_handler as *const () as usize;
            old.sa_flags = libc::SA_SIGINFO;
            assert_eq!(libc::sigemptyset(&mut old.sa_mask), 0);
            assert_eq!(libc::sigaddset(&mut old.sa_mask, inherited), 0);
            assert_eq!(libc::sigaction(signal, &old, std::ptr::null_mut()), 0);
        }

        let mut starting_mask: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut starting_mask), 0);
        assert_eq!(libc::sigaddset(&mut starting_mask, libc::SIGWINCH), 0);
        let mut original_mask: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, &starting_mask, &mut original_mask),
            0
        );

        // SAFETY: This binary owns the SIGSEGV/SIGBUS handlers. Both previous
        // handlers are static functions that remain installed for its lifetime.
        assert_eq!(kindasafe_init::init(), Ok(()));

        for (signal, inherited, other, observed) in [
            (libc::SIGSEGV, libc::SIGUSR1, libc::SIGUSR2, &SEGV_MASK),
            (libc::SIGBUS, libc::SIGUSR2, libc::SIGUSR1, &BUS_MASK),
        ] {
            let mut installed: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut installed), 0);
            assert_mask_member(&installed.sa_mask, libc::SIGPROF, 1);
            assert_mask_member(&installed.sa_mask, inherited, 1);
            assert_mask_member(&installed.sa_mask, other, 0);

            assert_thread_mask_restored();
            assert_eq!(libc::raise(signal), 0);
            // SIGPROF, the inherited mask, and the recovery signal are all
            // blocked during the callback. The unrelated signal stays open;
            // SIGWINCH was already blocked on this thread.
            assert_eq!(observed.load(Ordering::Relaxed), 0b11011);
            assert_thread_mask_restored();
        }

        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, &original_mask, std::ptr::null_mut()),
            0
        );
    }
}
