unsafe extern "C" {
    fn __asan_region_is_poisoned(addr: *const u8, len: usize) -> *const u8;
    fn __asan_report_load_n_noabort(addr: *const u8, len: usize);
}

/// Naked assembly bypasses compiler instrumentation. Check successful reads
/// explicitly; unreadable addresses still use normal signal recovery.
pub fn report_poisoned_load(at: u64, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: ASAN inspects shadow memory without dereferencing the source.
    // A successful assembly read establishes that this range does not wrap.
    unsafe {
        let bad = __asan_region_is_poisoned(at as *const u8, len);
        if !bad.is_null() {
            // Start at the first poisoned byte, including for unaligned loads
            // and ranges whose endpoints are both unpoisoned.
            let remaining = len - (bad as usize - at as usize);
            __asan_report_load_n_noabort(bad, remaining);
        }
    }
}
