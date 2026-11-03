// Keep libc calls in tests from changing the test thread's errno.
pub struct ErrnoGuard {
    ptr: *mut libc::c_int,
    previous: libc::c_int,
}

#[cfg(target_os = "linux")]
fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

impl ErrnoGuard {
    pub fn new() -> Self {
        let ptr = errno_ptr();
        Self {
            ptr,
            previous: unsafe { *ptr },
        }
    }
}

impl Drop for ErrnoGuard {
    fn drop(&mut self) {
        unsafe { *self.ptr = self.previous };
    }
}
