// Preserve errno across signal callbacks and calls made by test wrappers.
pub struct ErrnoGuard {
    ptr: *mut libc::c_int,
    previous: libc::c_int,
    restore: bool,
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
            restore: true,
        }
    }

    // A test wrapper that reports a libc error must leave that error in errno.
    #[allow(dead_code)]
    pub fn disarm(mut self) {
        self.restore = false;
    }
}

impl Drop for ErrnoGuard {
    fn drop(&mut self) {
        if self.restore {
            unsafe { *self.ptr = self.previous };
        }
    }
}
