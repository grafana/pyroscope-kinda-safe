use kindasafe_init::{InitError, RecoveryUnavailable, init, recovery_available, sanity_check};
use std::sync::atomic::{AtomicI32, Ordering};

static NESTED_STATUS: AtomicI32 = AtomicI32::new(-1);
static NESTED_SIGNAL: AtomicI32 = AtomicI32::new(-1);

extern "C" fn nested_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _data: *mut libc::c_void,
) {
    match recovery_available() {
        Ok(()) => NESTED_STATUS.store(0, Ordering::SeqCst),
        Err(RecoveryUnavailable::SignalBlocked(signal)) => {
            NESTED_STATUS.store(1, Ordering::SeqCst);
            NESTED_SIGNAL.store(signal, Ordering::SeqCst);
        }
        Err(_) => NESTED_STATUS.store(2, Ordering::SeqCst),
    }
}

extern "C" fn noop_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _data: *mut libc::c_void,
) {
}

fn signal_set(signals: &[libc::c_int]) -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut set), 0);
        for signal in signals {
            assert_eq!(libc::sigaddset(&mut set, *signal), 0);
        }
        set
    }
}

fn block(signals: &[libc::c_int]) -> libc::sigset_t {
    unsafe {
        let set = signal_set(signals);
        let mut old: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old), 0);
        old
    }
}

fn unblock(signals: &[libc::c_int]) {
    unsafe {
        let set = signal_set(signals);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()),
            0
        );
    }
}

fn restore_mask(old: libc::sigset_t) {
    unsafe {
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()),
            0
        );
    }
}

fn install_handler(
    signal: libc::c_int,
    handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
    masked: &[libc::c_int],
) -> libc::sigaction {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as usize;
        action.sa_flags = libc::SA_SIGINFO;
        action.sa_mask = signal_set(masked);

        let mut old: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(signal, &action, &mut old), 0);
        old
    }
}

fn restore_handler(signal: libc::c_int, old: libc::sigaction) {
    unsafe {
        assert_eq!(libc::sigaction(signal, &old, std::ptr::null_mut()), 0);
    }
}

#[test]
fn recovery_checks_initialization_handlers_and_masks() {
    assert_eq!(
        recovery_available(),
        Err(RecoveryUnavailable::NotInitialized)
    );

    init().expect("failed to initialize kindasafe");
    unblock(&[libc::SIGSEGV, libc::SIGBUS]);
    assert_eq!(recovery_available(), Ok(()));

    let old = block(&[libc::SIGSEGV]);
    assert_eq!(
        recovery_available(),
        Err(RecoveryUnavailable::SignalBlocked(libc::SIGSEGV))
    );
    assert_eq!(sanity_check(), Err(InitError::SanityCheckFailed));
    restore_mask(old);
    assert_eq!(recovery_available(), Ok(()));
    assert_eq!(sanity_check(), Ok(()));

    let old = block(&[libc::SIGBUS]);
    assert_eq!(
        recovery_available(),
        Err(RecoveryUnavailable::SignalBlocked(libc::SIGBUS))
    );
    restore_mask(old);
    assert_eq!(recovery_available(), Ok(()));

    // A nested signal handler inherits the interrupted handler's mask. This is
    // the profiling-interrupts-another-handler case from the issue.
    let old_handler = install_handler(libc::SIGUSR1, nested_handler, &[libc::SIGSEGV]);
    NESTED_STATUS.store(-1, Ordering::SeqCst);
    NESTED_SIGNAL.store(-1, Ordering::SeqCst);
    assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
    assert_eq!(NESTED_STATUS.load(Ordering::SeqCst), 1);
    assert_eq!(NESTED_SIGNAL.load(Ordering::SeqCst), libc::SIGSEGV);
    restore_handler(libc::SIGUSR1, old_handler);

    // Replacing a recovery handler after initialization must be detected.
    let old_handler = install_handler(libc::SIGSEGV, noop_handler, &[]);
    assert_eq!(
        recovery_available(),
        Err(RecoveryUnavailable::HandlerNotInstalled(libc::SIGSEGV))
    );
    restore_handler(libc::SIGSEGV, old_handler);
    assert_eq!(recovery_available(), Ok(()));
}
