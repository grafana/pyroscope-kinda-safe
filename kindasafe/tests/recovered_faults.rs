#![cfg(not(kindasafe_asan))]

// One test in its own integration-test process makes the cumulative count exact.
#[test]
fn counts_public_failures_only_including_concurrent_callers() {
    unsafe { kindasafe_init::init() }.unwrap();
    assert_eq!(kindasafe::recovered_faults(), 0);
    assert!(kindasafe::sanity_check());
    assert_eq!(kindasafe_init::sanity_check(), Ok(()));
    let value = 7u64;
    let at = &value as *const u64 as u64;
    unsafe {
        assert_eq!(kindasafe::u8(at).unwrap(), 7);
        assert_eq!(kindasafe::u32(at).unwrap(), 7);
        assert_eq!(kindasafe::u64(at).unwrap(), 7);
        let mut out = [0; 8];
        kindasafe::slice(&mut out, at).unwrap();
        assert_eq!(out, value.to_ne_bytes());
        kindasafe::slice(&mut [], 0).unwrap();
    }
    assert_eq!(kindasafe::recovered_faults(), 0);
    for round in 0..3 {
        unsafe {
            assert!(kindasafe::u8(0).is_err());
            assert!(kindasafe::u32(0).is_err());
            assert!(kindasafe::u64(0).is_err());
            assert!(kindasafe::slice(&mut [0; 8], 0).is_err());
        }
        assert_eq!(kindasafe::recovered_faults(), (round + 1) * 4);
    }
    // A copy that succeeds for its first eight bytes still counts only once.
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let map = libc::mmap(
            std::ptr::null_mut(),
            2 * page,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(map, libc::MAP_FAILED);
        assert_eq!(
            libc::mprotect(map, page, libc::PROT_READ | libc::PROT_WRITE),
            0
        );
        let mut out = [0; 16];
        assert!(kindasafe::slice(&mut out, (map as usize + page - 8) as u64).is_err());
        assert_eq!(libc::munmap(map, 2 * page), 0);
    }
    assert_eq!(kindasafe::recovered_faults(), 13);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..100 {
                    assert!(unsafe { kindasafe::u64(0) }.is_err());
                }
            });
        }
    });
    assert_eq!(kindasafe::recovered_faults(), 413);
}
