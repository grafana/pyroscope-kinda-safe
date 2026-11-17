#![cfg(kindasafe_asan)]

fn handler(signal: libc::c_int) -> libc::sigaction {
    unsafe {
        let mut action = std::mem::zeroed();
        assert_eq!(libc::sigaction(signal, std::ptr::null(), &mut action), 0);
        action
    }
}

#[test]
fn initialization_and_sanity_checks_leave_handlers_untouched() {
    let before = [handler(libc::SIGSEGV), handler(libc::SIGBUS)];
    assert_eq!(kindasafe_init::is_initialized(), None);
    // These must work even before init, when no recovery handlers exist.
    assert!(kindasafe::sanity_check());
    assert_eq!(kindasafe_init::sanity_check(), Ok(()));
    for _ in 0..2 {
        unsafe { kindasafe_init::init() }.unwrap();
        assert_eq!(kindasafe_init::is_initialized(), Some(Ok(())));
    }
    for (signal, old) in [libc::SIGSEGV, libc::SIGBUS].into_iter().zip(before) {
        let after = handler(signal);
        assert_eq!(after.sa_sigaction, old.sa_sigaction);
        assert_eq!(after.sa_flags, old.sa_flags);
        for member in 1..=64 {
            unsafe {
                assert_eq!(
                    libc::sigismember(&after.sa_mask, member),
                    libc::sigismember(&old.sa_mask, member)
                );
            }
        }
    }
    assert!(kindasafe::crash_points().crash_points.is_empty());
    assert_eq!(kindasafe::recovered_faults(), 0);
}
