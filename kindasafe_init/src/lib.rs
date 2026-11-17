use std::sync::Mutex;
#[cfg(not(kindasafe_asan))]
mod recovery;

#[derive(Debug, PartialEq, Clone)]
pub enum InitError {
    InstallSignalHandlersFailed,
    UnsupportedPreviousHandler,
    SanityCheckFailed,
}

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
/// ASan builds cache success without querying or changing signal handlers.
/// The installation requirements below apply only to normal builds.
///
/// Calls to this function are serialized. The installed handlers inherit the
/// flags and signal masks of the previous handlers, such as `SA_ONSTACK` and
/// `SA_NODEFER`, and also block `SIGPROF` while they run or call a previous
/// handler. A sampling handler must still check that SIGSEGV and SIGBUS are
/// unblocked on its thread before attempting a protected read.
///
/// # Errors
/// Returns `UnsupportedPreviousHandler` and changes nothing if a previous
/// SIGSEGV or SIGBUS handler was installed with `SA_RESETHAND`, or on macOS
/// is `SIG_IGN`. macOS does not report `SA_RESETHAND`, so there such a handler
/// is accepted and called on every signal that is not recovered, not only the
/// first.
///
/// If SIGBUS installation fails, initialization attempts to restore the
/// previous SIGSEGV handler before returning `InstallSignalHandlersFailed`.
/// If restoration also fails, the SIGSEGV recovery handler remains installed
/// while SIGBUS keeps its previous handler. Recovery must not be used after
/// initialization fails. All results, including failures, are cached.
///
/// # Safety
/// The caller must coordinate installation with other code that changes how
/// SIGSEGV or SIGBUS are handled: reading the current setup and installing ours
/// are separate syscalls.
///
/// Previous handlers must support direct chaining and remain valid for as long
/// as our handlers can call them. SIG_DFL and SIG_IGN are honored
/// without calling anything.
pub unsafe fn init() -> Result<(), InitError> {
    let mut g = INIT_LOCK.lock().expect("initialization lock poisoned");
    if let Some(prev) = g.clone() {
        return prev;
    }

    #[cfg(not(kindasafe_asan))]
    let res = recovery::init_locked();
    #[cfg(kindasafe_asan)]
    let res = Ok(());
    *g = Some(res.clone());
    res
}

pub fn restore_default_ignal_handler(sig: libc::c_int) {
    let action: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) };
}

/// Sanity check that kindasafe crash recovery is working.
///
/// Normal builds attempt to read address 239 without incrementing the recovered
/// fault counter. ASan builds return `Ok(())` without attempting a read.
///
/// Returns `Ok(())` if the sanity check passes, `Err(SanityCheckFailed)` if
/// the read unexpectedly succeeded (meaning crash recovery is broken).
pub fn sanity_check() -> Result<(), InitError> {
    if kindasafe::sanity_check() {
        Ok(())
    } else {
        Err(InitError::SanityCheckFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_idempotent() {
        // SAFETY: These tests only change signal handling through init().
        assert!(unsafe { init() }.is_ok());
        assert!(unsafe { init() }.is_ok());
        assert!(is_initialized().is_some());
        assert_eq!(is_initialized(), Some(Ok(())));
    }

    #[test]
    fn test_sanity_check() {
        // SAFETY: These tests only change signal handling through init().
        assert!(unsafe { init() }.is_ok());
        assert!(sanity_check().is_ok());
    }
}
