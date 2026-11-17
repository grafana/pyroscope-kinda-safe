#![cfg(not(kindasafe_asan))]
// On Linux, this test's sigaction function intercepts calls to libc's sigaction.
// It calls the real function, then delivers signals before returning to the
// initialization code. This checks that the fallback is ready as soon as the
// new handler becomes active, even before the installation call returns.
// Failed installations must attempt to restore the previous handlers without
// retrying either operation on later calls, even if restoration also fails.
#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

#[path = "common/errno_guard.rs"]
mod errno_guard;
use errno_guard::ErrnoGuard;

static INTERPOSE: AtomicBool = AtomicBool::new(false);
static FAIL_SIGNAL: AtomicI32 = AtomicI32::new(0);
static FAIL_RESTORE: AtomicBool = AtomicBool::new(false);
static INSTALLS: AtomicUsize = AtomicUsize::new(0);
static RESTORES: AtomicUsize = AtomicUsize::new(0);
static SEGV_CALLS: AtomicUsize = AtomicUsize::new(0);
static BUS_CALLS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn previous_handler(
    signal: libc::c_int,
    _info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    calls(signal).fetch_add(1, Ordering::Relaxed);
}

fn calls(signal: libc::c_int) -> &'static AtomicUsize {
    match signal {
        libc::SIGSEGV => &SEGV_CALLS,
        libc::SIGBUS => &BUS_CALLS,
        _ => unreachable!(),
    }
}

fn current_handler(signal: libc::c_int) -> libc::sigaction {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut action), 0);
        action
    }
}

fn assert_previous_handler(signal: libc::c_int, previous: &libc::sigaction) {
    let current = current_handler(signal);
    assert_eq!(current.sa_sigaction, previous.sa_sigaction);
    assert_eq!(current.sa_flags, previous.sa_flags);
    for masked_signal in 1..=libc::SIGRTMAX() {
        assert_eq!(
            unsafe { libc::sigismember(&current.sa_mask, masked_signal) },
            unsafe { libc::sigismember(&previous.sa_mask, masked_signal) },
            "signal {signal}, mask entry {masked_signal}",
        );
    }
}

fn deliver_on_both_threads(signal: libc::c_int) {
    let _errno_guard = ErrnoGuard::new();
    let before = calls(signal).load(Ordering::Relaxed);
    assert_eq!(unsafe { libc::raise(signal) }, 0);
    std::thread::spawn(move || {
        let _errno_guard = ErrnoGuard::new();
        assert_eq!(unsafe { libc::raise(signal) }, 0);
    })
    .join()
    .unwrap();
    assert_eq!(calls(signal).load(Ordering::Relaxed), before + 2);
}

// Export the exact symbol name `sigaction` so this test intercepts libc calls.
// SAFETY: The wrapper matches libc's C ABI and signature; the symbol override
// is intentional and confined to this test executable.
#[unsafe(no_mangle)]
unsafe extern "C" fn sigaction(
    signal: libc::c_int,
    action: *const libc::sigaction,
    old: *mut libc::sigaction,
) -> libc::c_int {
    let errno_guard = ErrnoGuard::new();
    type Sigaction = unsafe extern "C" fn(
        libc::c_int,
        *const libc::sigaction,
        *mut libc::sigaction,
    ) -> libc::c_int;
    let real = unsafe { libc::dlsym(libc::RTLD_NEXT, c"sigaction".as_ptr()) };
    assert!(!real.is_null());
    let real: Sigaction = unsafe { std::mem::transmute(real) };
    let changing = INTERPOSE.load(Ordering::Relaxed)
        && !action.is_null()
        && unsafe { (*action).sa_sigaction != libc::SIG_DFL }
        && matches!(signal, libc::SIGSEGV | libc::SIGBUS);
    let restoring =
        changing && unsafe { (*action).sa_sigaction == previous_handler as *const () as usize };
    let installing = changing && !restoring;
    if restoring {
        assert_eq!(signal, libc::SIGSEGV);
        RESTORES.fetch_add(1, Ordering::Relaxed);
        deliver_on_both_threads(signal);
        if FAIL_RESTORE.load(Ordering::Relaxed) {
            errno_guard.disarm();
            unsafe { *libc::__errno_location() = libc::EINVAL };
            return -1;
        }
    }
    if installing {
        INSTALLS.fetch_add(1, Ordering::Relaxed);
        deliver_on_both_threads(signal);
        if FAIL_SIGNAL.load(Ordering::Relaxed) == signal {
            errno_guard.disarm();
            unsafe { *libc::__errno_location() = libc::EINVAL };
            return -1;
        }
    }
    let result = unsafe { real(signal, action, old) };
    if changing && result == 0 {
        deliver_on_both_threads(signal);
    }
    if result != 0 {
        errno_guard.disarm();
    }
    result
}

#[test]
fn installation_boundaries() {
    const CHILD_MODE: &str = "KINDASAFE_TEST_FAIL_SIGNAL";
    const CHILD_RESTORE_MODE: &str = "KINDASAFE_TEST_FAIL_RESTORE";
    let Ok(fail_signal) = std::env::var(CHILD_MODE) else {
        // Each case needs fresh process-global signal and initialization state.
        for (fail_signal, fail_restore) in [
            (0, false),
            (libc::SIGSEGV, false),
            (libc::SIGBUS, false),
            (libc::SIGBUS, true),
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "installation_boundaries", "--nocapture"])
                .env(CHILD_MODE, fail_signal.to_string())
                .env(CHILD_RESTORE_MODE, fail_restore.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "failure signal {fail_signal}, restore failure {fail_restore}: {}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        return;
    };
    let fail_signal: i32 = fail_signal.parse().unwrap();
    let fail_restore: bool = std::env::var(CHILD_RESTORE_MODE).unwrap().parse().unwrap();
    unsafe {
        // Disable core dumps: if fallback chaining breaks, the test signal
        // may terminate this child process.
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &limit), 0);
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = previous_handler as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        for (signal, masked_signal) in [
            (libc::SIGSEGV, libc::SIGUSR1),
            (libc::SIGBUS, libc::SIGUSR2),
        ] {
            assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
            assert_eq!(libc::sigaddset(&mut action.sa_mask, masked_signal), 0);
            assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
        }
    }
    let previous = [
        current_handler(libc::SIGSEGV),
        current_handler(libc::SIGBUS),
    ];
    FAIL_SIGNAL.store(fail_signal, Ordering::Relaxed);
    FAIL_RESTORE.store(fail_restore, Ordering::Relaxed);
    INTERPOSE.store(true, Ordering::Relaxed);
    let expected = if fail_signal == 0 {
        Ok(())
    } else {
        Err(kindasafe_init::InitError::InstallSignalHandlersFailed)
    };
    let start = std::sync::Barrier::new(4);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let start = &start;
            let expected = &expected;
            scope.spawn(move || {
                start.wait();
                // SAFETY: previous_handler is a static SA_SIGINFO handler, and
                // its installation finished before these threads were started.
                let result = unsafe { kindasafe_init::init() };
                assert_eq!(&result, expected);
            });
        }
    });
    assert_eq!(kindasafe_init::is_initialized(), Some(expected.clone()));
    let installs = INSTALLS.load(Ordering::Relaxed);
    assert_eq!(installs, if fail_signal == libc::SIGSEGV { 1 } else { 2 });
    let restores = RESTORES.load(Ordering::Relaxed);
    assert_eq!(restores, usize::from(fail_signal == libc::SIGBUS));

    // Repeated initialization calls must not reinstall handlers or repeat a
    // rollback, and must preserve the fallback after successful installation.
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                // SAFETY: The same fallback remains valid; only init() changes
                // signal handling in this child after the initial setup.
                assert_eq!(unsafe { kindasafe_init::init() }, expected);
            });
        }
    });
    assert_eq!(INSTALLS.load(Ordering::Relaxed), installs);
    assert_eq!(RESTORES.load(Ordering::Relaxed), restores);
    for (signal, previous) in [libc::SIGSEGV, libc::SIGBUS].into_iter().zip(&previous) {
        if fail_signal != 0 && !(fail_restore && signal == libc::SIGSEGV) {
            assert_previous_handler(signal, previous);
        } else {
            assert_ne!(current_handler(signal).sa_sigaction, previous.sa_sigaction);
        }
        deliver_on_both_threads(signal);
    }
    if fail_signal == 0 {
        assert_eq!(kindasafe_init::sanity_check(), Ok(()));
    }
    assert_eq!(kindasafe::recovered_faults(), 0);
}
