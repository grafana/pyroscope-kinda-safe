// On Linux, this test's sigaction function intercepts calls to libc's sigaction.
// It calls the real function, then delivers signals before returning to the
// initialization code. This checks that the fallback is ready as soon as the
// new handler becomes active, even before the installation call returns.
#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

static INTERPOSE: AtomicBool = AtomicBool::new(false);
static FAIL_SIGNAL: AtomicI32 = AtomicI32::new(0);
static INSTALLS: AtomicUsize = AtomicUsize::new(0);
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

fn deliver_on_both_threads(signal: libc::c_int) {
    let before = calls(signal).load(Ordering::Relaxed);
    assert_eq!(unsafe { libc::raise(signal) }, 0);
    std::thread::spawn(move || assert_eq!(unsafe { libc::raise(signal) }, 0))
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
    type Sigaction = unsafe extern "C" fn(
        libc::c_int,
        *const libc::sigaction,
        *mut libc::sigaction,
    ) -> libc::c_int;
    let real = unsafe { libc::dlsym(libc::RTLD_NEXT, c"sigaction".as_ptr()) };
    assert!(!real.is_null());
    let real: Sigaction = unsafe { std::mem::transmute(real) };
    let installing = INTERPOSE.load(Ordering::Relaxed)
        && !action.is_null()
        && unsafe { (*action).sa_sigaction != libc::SIG_DFL }
        && matches!(signal, libc::SIGSEGV | libc::SIGBUS);
    if installing {
        INSTALLS.fetch_add(1, Ordering::Relaxed);
        deliver_on_both_threads(signal);
        if FAIL_SIGNAL.load(Ordering::Relaxed) == signal {
            unsafe { *libc::__errno_location() = libc::EINVAL };
            return -1;
        }
    }
    let result = unsafe { real(signal, action, old) };
    if installing && result == 0 {
        deliver_on_both_threads(signal);
    }
    result
}

#[test]
fn installation_boundaries() {
    const CHILD_MODE: &str = "KINDASAFE_TEST_FAIL_SIGNAL";
    let Ok(fail_signal) = std::env::var(CHILD_MODE) else {
        // Each case needs fresh process-global signal and initialization state.
        for fail_signal in [0, libc::SIGSEGV, libc::SIGBUS] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "installation_boundaries", "--nocapture"])
                .env(CHILD_MODE, fail_signal.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "failure signal {fail_signal}: {}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        return;
    };
    let fail_signal: i32 = fail_signal.parse().unwrap();
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
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGSEGV, libc::SIGBUS] {
            assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
        }
    }
    FAIL_SIGNAL.store(fail_signal, Ordering::Relaxed);
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

    // Repeated initialization calls must not overwrite the
    // fallback with crash_handler, including after a partial installation.
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                // SAFETY: The same fallback remains valid; only init() changes
                // signal dispositions in this child after the initial setup.
                assert_eq!(unsafe { kindasafe_init::init() }, expected);
            });
        }
    });
    assert_eq!(INSTALLS.load(Ordering::Relaxed), installs);
    for signal in [libc::SIGSEGV, libc::SIGBUS] {
        deliver_on_both_threads(signal);
    }
    if fail_signal != libc::SIGSEGV {
        assert_eq!(kindasafe_init::sanity_check(), Ok(()));
    }
}
