use std::env;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use libc::{c_int, c_void, siginfo_t};

const SCENARIO_ENV: &str = "KINDASAFE_FALLBACK_SCENARIO";

fn run_self_child(test_name: &str, scenario: &str) -> ExitStatus {
    Command::new(env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env(SCENARIO_ENV, scenario)
        .status()
        .expect("spawn test child")
}

fn scenario() -> Option<String> {
    env::var(SCENARIO_ENV).ok()
}

fn install_action(signal: c_int, handler: usize, flags: c_int) {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        action.sa_sigaction = handler;
        action.sa_flags = flags;
        assert_eq!(
            libc::sigaction(signal, &action, std::ptr::null_mut()),
            0,
            "sigaction failed for signal {signal}"
        );
    }
}

fn disable_core_dumps() {
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

#[test]
fn fallback_sig_ign_sigbus_is_ignored() {
    if scenario().as_deref() == Some("sig_ign_sigbus") {
        disable_core_dumps();
        install_action(libc::SIGBUS, libc::SIG_IGN, 0);

        // The application ignored SIGBUS before kindasafe was initialized.
        assert_eq!(unsafe { libc::raise(libc::SIGBUS) }, 0);
        assert!(kindasafe_init::init().is_ok());
        // A user-generated SIGBUS must still be ignored after initialization.
        assert_eq!(unsafe { libc::raise(libc::SIGBUS) }, 0);
        return;
    }

    let status = run_self_child("fallback_sig_ign_sigbus_is_ignored", "sig_ign_sigbus");
    assert!(
        status.success(),
        "ignored SIGBUS killed the child: {status:?}"
    );
}

#[test]
fn fallback_sig_dfl_sigbus_applies_default_action() {
    if scenario().as_deref() == Some("sig_dfl_sigbus") {
        disable_core_dumps();
        install_action(libc::SIGBUS, libc::SIG_DFL, 0);
        assert!(kindasafe_init::init().is_ok());

        assert_eq!(unsafe { libc::raise(libc::SIGBUS) }, 0);
        panic!("SIGBUS default action was not applied to the raised signal");
    }

    let status = run_self_child(
        "fallback_sig_dfl_sigbus_applies_default_action",
        "sig_dfl_sigbus",
    );
    assert_eq!(
        status.signal(),
        Some(libc::SIGBUS),
        "expected default SIGBUS termination, got {status:?}"
    );
}

static LEGACY_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn legacy_handler(sig: c_int) {
    LEGACY_SIGNAL.store(sig, Ordering::SeqCst);
}

#[test]
fn fallback_calls_one_argument_handler() {
    if scenario().as_deref() == Some("one_argument") {
        disable_core_dumps();
        install_action(libc::SIGBUS, legacy_handler as *const () as usize, 0);
        assert!(kindasafe_init::init().is_ok());

        LEGACY_SIGNAL.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { libc::raise(libc::SIGBUS) }, 0);
        assert_eq!(LEGACY_SIGNAL.load(Ordering::SeqCst), libc::SIGBUS);
        return;
    }

    let status = run_self_child("fallback_calls_one_argument_handler", "one_argument");
    assert!(
        status.success(),
        "one-argument fallback handler was not called: {status:?}"
    );
}

static SIGINFO_SIGNAL: AtomicI32 = AtomicI32::new(0);
static SIGINFO_HAS_MATCHING_SIGNO: AtomicBool = AtomicBool::new(false);
static SIGINFO_HAS_CONTEXT: AtomicBool = AtomicBool::new(false);

extern "C" fn siginfo_handler(sig: c_int, info: *mut siginfo_t, context: *mut c_void) {
    SIGINFO_SIGNAL.store(sig, Ordering::SeqCst);
    let has_matching_signo = unsafe { !info.is_null() && (*info).si_signo == sig };
    SIGINFO_HAS_MATCHING_SIGNO.store(has_matching_signo, Ordering::SeqCst);
    SIGINFO_HAS_CONTEXT.store(!context.is_null(), Ordering::SeqCst);
}

#[test]
fn fallback_calls_siginfo_handler_with_siginfo_arguments() {
    if scenario().as_deref() == Some("siginfo") {
        disable_core_dumps();
        install_action(
            libc::SIGBUS,
            siginfo_handler as *const () as usize,
            libc::SA_SIGINFO,
        );
        assert!(kindasafe_init::init().is_ok());

        SIGINFO_SIGNAL.store(0, Ordering::SeqCst);
        SIGINFO_HAS_MATCHING_SIGNO.store(false, Ordering::SeqCst);
        SIGINFO_HAS_CONTEXT.store(false, Ordering::SeqCst);
        assert_eq!(unsafe { libc::raise(libc::SIGBUS) }, 0);
        assert_eq!(SIGINFO_SIGNAL.load(Ordering::SeqCst), libc::SIGBUS);
        assert!(SIGINFO_HAS_MATCHING_SIGNO.load(Ordering::SeqCst));
        assert!(SIGINFO_HAS_CONTEXT.load(Ordering::SeqCst));
        return;
    }

    let status = run_self_child(
        "fallback_calls_siginfo_handler_with_siginfo_arguments",
        "siginfo",
    );
    assert!(
        status.success(),
        "SA_SIGINFO fallback handler did not receive its arguments: {status:?}"
    );
}
