unsafe extern "C" {
    fn __asan_region_is_poisoned(addr: *const u8, len: usize) -> *const u8;
    fn __asan_report_load_n_noabort(addr: *const u8, len: usize);
}

/// Naked assembly bypasses compiler instrumentation. Check readable source
/// bytes for poison explicitly; the recovery path reports faulting reads below.
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

/// The recovery handler can turn an unmapped read into `Err`, hiding it from
/// ASAN. Report that attempted read after recovery has finished. ASAN describes
/// unmapped addresses as an unknown crash because they have no poisoned shadow.
pub fn report_faulting_load(at: u64, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: this ASAN entry point reports the address without loading from it.
    unsafe { __asan_report_load_n_noabort(at as *const u8, len) }
}
