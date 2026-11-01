// Each scenario installs a previous handler for SIGSEGV and SIGBUS, runs
// init(), then delivers a signal that no crash point recovers from. The
// previous handler must then be honored: ignored signals return, SIG_DFL
// terminates the process, and handlers are called with the signature their
// SA_SIGINFO flag selects. Previous handlers installed with SA_RESETHAND are
// rejected by init() and left in place.

use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

const SCENARIO: &str = "KINDASAFE_TEST_FALLBACK_SCENARIO";
const SIGNAL: &str = "KINDASAFE_TEST_FALLBACK_SIGNAL";

static CALLS: AtomicUsize = AtomicUsize::new(0);
static LAST_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn plain_handler(signal: libc::c_int) {
    CALLS.fetch_add(1, Ordering::Relaxed);
    LAST_SIGNAL.store(signal, Ordering::Relaxed);
}

extern "C" fn siginfo_handler(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    assert!(!info.is_null());
    assert!(!context.is_null());
    assert_eq!(unsafe { (*info).si_signo }, signal);
    CALLS.fetch_add(1, Ordering::Relaxed);
    LAST_SIGNAL.store(signal, Ordering::Relaxed);
}

fn install(handler: usize, flags: libc::c_int) {
    for signal in [libc::SIGSEGV, libc::SIGBUS] {
        install_one(signal, handler, flags);
    }
}

fn install_one(signal: libc::c_int, handler: usize, flags: libc::c_int) {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        action.sa_flags = flags;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
    }
}

fn current_handler(signal: libc::c_int) -> libc::sigaction {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        assert_eq!(
            libc::sigaction(signal, std::ptr::null_mut(), &mut action),
            0
        );
        action
    }
}

fn disable_core_dumps() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
}

fn fault_outside_kindasafe() {
    unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(page, libc::MAP_FAILED);
        std::ptr::read_volatile(page as *const u8);
    }
}

fn raise(signal: libc::c_int) {
    assert_eq!(unsafe { libc::raise(signal) }, 0);
}

fn run_child(scenario: &str, signal: libc::c_int) -> std::process::ExitStatus {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "fallback_dispositions", "--nocapture"])
        .env(SCENARIO, scenario)
        .env(SIGNAL, signal.to_string())
        .output()
        .unwrap();
    eprintln!(
        "scenario {scenario} signal {signal}: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output.status
}

fn child(scenario: &str, signal: libc::c_int) {
    disable_core_dumps();
    match scenario {
        "ignored_raise" => {
            install(libc::SIG_IGN, 0);
            unsafe { kindasafe_init::init() }.unwrap();
            raise(signal);
            raise(signal);
            assert_eq!(kindasafe_init::sanity_check(), Ok(()));
        }
        "ignored_fault" => {
            install(libc::SIG_IGN, 0);
            unsafe { kindasafe_init::init() }.unwrap();
            assert_eq!(kindasafe_init::sanity_check(), Ok(()));
            fault_outside_kindasafe();
            unreachable!("ignored hardware fault must terminate the process");
        }
        "default_raise" => {
            install(libc::SIG_DFL, 0);
            unsafe { kindasafe_init::init() }.unwrap();
            assert_eq!(kindasafe_init::sanity_check(), Ok(()));
            raise(signal);
            unreachable!("SIG_DFL must terminate the process");
        }
        "default_fault" => {
            install(libc::SIG_DFL, 0);
            unsafe { kindasafe_init::init() }.unwrap();
            assert_eq!(kindasafe_init::sanity_check(), Ok(()));
            fault_outside_kindasafe();
            unreachable!("SIG_DFL must terminate the process");
        }
        "plain_handler" => {
            install(plain_handler as *const () as usize, 0);
            unsafe { kindasafe_init::init() }.unwrap();
            raise(signal);
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(LAST_SIGNAL.load(Ordering::Relaxed), signal);
            assert_eq!(kindasafe_init::sanity_check(), Ok(()));
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        }
        "siginfo_handler" => {
            install(siginfo_handler as *const () as usize, libc::SA_SIGINFO);
            unsafe { kindasafe_init::init() }.unwrap();
            raise(signal);
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(LAST_SIGNAL.load(Ordering::Relaxed), signal);
            assert_eq!(kindasafe_init::sanity_check(), Ok(()));
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        }
        "resethand_rejected" => {
            let handler = siginfo_handler as *const () as usize;
            install(handler, libc::SA_SIGINFO | libc::SA_RESETHAND);
            assert_eq!(
                unsafe { kindasafe_init::init() },
                Err(kindasafe_init::InitError::UnsupportedPreviousHandler)
            );
            assert_eq!(
                kindasafe_init::is_initialized(),
                Some(Err(kindasafe_init::InitError::UnsupportedPreviousHandler))
            );
            let current = current_handler(signal);
            assert_eq!(current.sa_sigaction, handler);
            assert_ne!(current.sa_flags & libc::SA_RESETHAND, 0);
            raise(signal);
            assert_eq!(CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(LAST_SIGNAL.load(Ordering::Relaxed), signal);
        }
        "resethand_sigbus_only" => {
            let handler = siginfo_handler as *const () as usize;
            install_one(libc::SIGSEGV, handler, libc::SA_SIGINFO);
            install_one(libc::SIGBUS, handler, libc::SA_SIGINFO | libc::SA_RESETHAND);
            assert_eq!(
                unsafe { kindasafe_init::init() },
                Err(kindasafe_init::InitError::UnsupportedPreviousHandler)
            );
            assert_eq!(current_handler(libc::SIGSEGV).sa_sigaction, handler);
            assert_eq!(current_handler(libc::SIGBUS).sa_sigaction, handler);
        }
        _ => unreachable!("unknown scenario {scenario}"),
    }
}

#[test]
fn fallback_dispositions() {
    if let Ok(scenario) = std::env::var(SCENARIO) {
        let signal: i32 = std::env::var(SIGNAL).unwrap().parse().unwrap();
        child(&scenario, signal);
        return;
    }
    for signal in [libc::SIGSEGV, libc::SIGBUS] {
        for scenario in [
            "ignored_raise",
            "plain_handler",
            "siginfo_handler",
            "resethand_rejected",
            "resethand_sigbus_only",
        ] {
            let status = run_child(scenario, signal);
            assert!(status.success(), "{scenario} {signal}: {status}");
        }
        for scenario in ["default_raise", "default_fault", "ignored_fault"] {
            let status = run_child(scenario, signal);
            let expected = if scenario.ends_with("_fault") {
                fault_signal()
            } else {
                signal
            };
            assert_eq!(
                status.signal(),
                Some(expected),
                "{scenario} {signal}: {status}"
            );
        }
    }
}

fn fault_signal() -> libc::c_int {
    if cfg!(target_os = "macos") {
        libc::SIGBUS
    } else {
        libc::SIGSEGV
    }
}
