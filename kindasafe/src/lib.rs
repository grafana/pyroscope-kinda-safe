#![no_std]

#[derive(Debug, PartialEq)]
pub struct ReadMemError {
    pub signal: u64,
}

pub type Ptr = u64;

/// Reads a 64-bit value from the address `at`.
///
/// # Safety
///
/// The caller must ensure all of the following:
///
/// - If `at..at + 8` is readable, it refers to an initialized 8-byte value in a
///   live allocation. The range must not be concurrently mutated, and no
///   conflicting Rust reference may be used for the duration of the call.
/// - If any part of `at..at + 8` is not readable, the `kindasafe_init` handlers
///   must have been installed process-wide (normally by a successful
///   `kindasafe_init::init()` call, which may run on any thread) and must remain
///   installed. The relevant fault signal must be deliverable on the calling
///   thread (not blocked), and the installed handler must be able to recover
///   from the fault. Recovery is a speculative-read mechanism, not a substitute
///   for a valid pointer: a failed recovery may terminate the process or
///   deliver the fault to an application handler.
///
/// The read must not race with any other access to the same memory.
pub unsafe fn u64(at: Ptr) -> Result<Ptr, ReadMemError> {
    let res = unsafe { arch::u64(at) };
    if res.signal == 0 {
        Ok(res.value)
    } else {
        Err(ReadMemError { signal: res.signal })
    }
}

/// Copies `buf.len()` bytes from the address `at` into `buf`.
///
/// If the copy faults, `buf` may contain a prefix of the source bytes even
/// though this function returns an error.
///
/// # Safety
///
/// The caller must ensure all of the following:
///
/// - If `at..at + buf.len()` is readable, it refers to initialized bytes in a
///   live allocation. The source range must not be concurrently mutated or
///   aliased by a conflicting reference or access for the duration of the
///   copy. In particular, it must not overlap `buf` unless the caller rules
///   out conflicting accesses.
/// - If any source byte is not readable, the same recovery-handler, signal
///   delivery and reentrancy requirements as for [`u64()`] apply.
/// - `buf` must remain uniquely borrowed for the duration of the call. No other
///   thread or signal handler may access it concurrently.
pub unsafe fn slice(buf: &mut [u8], at: Ptr) -> Result<(), ReadMemError> {
    let res = unsafe { arch::slice(buf.as_ptr(), at, buf.len() as u64) };
    if res.signal == 0 {
        Ok(())
    } else {
        Err(ReadMemError { signal: res.signal })
    }
}

/// Copies up to `buf.len()` bytes from the address `at` into `buf` and returns
/// the NUL-terminated prefix as a UTF-8 string.
///
/// If `at == 0`, this returns `Ok("")` without reading memory.
///
/// # Safety
///
/// The caller must uphold the same source address, initialization, aliasing,
/// concurrency and fault-recovery requirements as for [`slice()`]. Note that the
/// entire source range of length `buf.len()` is copied, not only the bytes up
/// to the first NUL. On error, `buf` may have been partially overwritten.
pub unsafe fn str(buf: &mut [u8], at: Ptr) -> Result<&str, ReadMemError> {
    if at == 0 {
        return Ok("");
    }
    let res = unsafe { arch::slice(buf.as_ptr(), at, buf.len() as u64) };
    if res.signal != 0 {
        return Err(ReadMemError { signal: res.signal });
    }
    for i in 0..buf.len() {
        if buf[i] == 0 {
            let v = &buf[..i];
            return match core::str::from_utf8(v) {
                Ok(v) => Ok(v),
                Err(_) => Err(ReadMemError { signal: 228 }), //todo
            };
        }
    }
    Err(ReadMemError { signal: 229 }) //todo
}

pub fn crash_points() -> CrashPoints {
    arch::crash_points()
}

#[derive(Copy, Clone)]
pub struct CrashPoint {
    pub pc: usize,
    pub signal_reg: Reg,
    pub skip: usize,
}
const CRASH_POINTS_COUNT: usize = 2;

#[derive(Copy, Clone)]
pub struct CrashPoints {
    pub crash_points: [CrashPoint; CRASH_POINTS_COUNT],
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Reg {
    Rax,
    Rdx,
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Reg {
    X0,
    X1,
}

#[cfg(target_arch = "x86_64")]
pub mod arch {

    #[repr(C)]
    pub struct U64Res {
        pub value: u64,
        pub signal: u64,
    }

    /// # Safety
    ///
    /// See [`crate::u64()`]. `_at` must be valid for a 64-bit read, or a fault at
    /// that address must be recoverable by the installed handlers. The read
    /// must not race with concurrent accesses. The caller must also ensure that
    /// a successful return contains an initialized value.
    #[unsafe(naked)]
    pub unsafe extern "sysv64" fn u64(_at: u64) -> U64Res {
        core::arch::naked_asm!(
            "mov rax, [rdi]", // 00010000 	48 8B 07 	mov 	rax, qword ptr [rdi]
            "xor edx, edx",   // 00010003 	31 D2 	xor 	edx, edx
            "ret",            // 00010005 	C3 	ret
        )
    }

    #[repr(C)]
    pub struct VecResult {
        pub signal: u64,
    }

    /// # Safety
    ///
    /// `_dst` must be valid for writes of `_n` bytes and must be uniquely
    /// writable for the duration of the call. `_src` must be valid for reads of
    /// `_n` initialized bytes, or any fault must be recoverable by the
    /// installed handlers; the source must not be concurrently mutated or
    /// conflict with `_dst`. The caller is responsible for ensuring `_n` fits
    /// the destination allocation; unlike [`crate::slice()`], this function has
    /// no destination-length information. Signal-delivery and reentrancy
    /// requirements are the same as for [`crate::u64()`].
    #[unsafe(naked)]
    pub unsafe extern "sysv64" fn slice(
        _dst: *const u8, // rdi
        _src: u64,       // rsi
        _n: u64,         // rdx
    ) -> VecResult {
        core::arch::naked_asm!(
            "mov ecx, edx", // 00010000 	89 D1 	mov 	ecx, edx
            "rep movsb",    // 00010002 	F3 A4 	rep movsb 	byte ptr [rdi], byte ptr [rsi]
            "xor eax, eax", // 00010004 	31 C0 	xor 	eax, eax
            "ret",          // 00010006 	C3 	ret
        )
    }

    pub fn crash_points() -> crate::CrashPoints {
        crate::CrashPoints {
            crash_points: [
                crate::CrashPoint {
                    pc: u64 as *const () as usize,
                    signal_reg: crate::Reg::Rdx,
                    skip: 5,
                },
                crate::CrashPoint {
                    pc: slice as *const () as usize + 2, // +2 for 89 D1 	mov 	ecx, edx
                    signal_reg: crate::Reg::Rax,
                    skip: 4,
                },
            ],
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub mod arch {

    #[repr(C)]
    pub struct U64Res {
        pub value: u64,
        pub signal: u64,
    }

    /// # Safety
    ///
    /// See [`crate::u64()`]. `_at` must be valid for a 64-bit read, or a fault at
    /// that address must be recoverable by the installed handlers. The read
    /// must not race with concurrent accesses. The caller must also ensure that
    /// a successful return contains an initialized value.
    #[unsafe(naked)]
    pub unsafe extern "C" fn u64(_at: u64) -> U64Res {
        core::arch::naked_asm!(
            "ldr x0, [x0]", // offset 0: load 64-bit value from address in x0
            "mov x1, #0",   // offset 4: signal = 0 (success)
            "ret",          // offset 8
        )
    }

    #[repr(C)]
    pub struct VecResult {
        pub signal: u64,
    }

    /// # Safety
    ///
    /// `_dst` must be valid for writes of `_n` bytes and must be uniquely
    /// writable for the duration of the call. `_src` must be valid for reads of
    /// `_n` initialized bytes, or any fault must be recoverable by the
    /// installed handlers; the source must not be concurrently mutated or
    /// conflict with `_dst`. The caller is responsible for ensuring `_n` fits
    /// the destination allocation; unlike [`crate::slice()`], this function has
    /// no destination-length information. Signal-delivery and reentrancy
    /// requirements are the same as for [`crate::u64()`].
    #[unsafe(naked)]
    pub unsafe extern "C" fn slice(
        _dst: *const u8, // x0
        _src: u64,       // x1
        _n: u64,         // x2
    ) -> VecResult {
        core::arch::naked_asm!(
            "cbz x2, 2f", // offset 0: skip if n==0
            "1:",
            "ldrb w3, [x1], #1", // offset 4: load byte from src, post-increment
            "strb w3, [x0], #1", // offset 8: store byte to dst, post-increment
            "subs x2, x2, #1",   // offset 12: decrement counter
            "b.ne 1b",           // offset 16: loop if not zero
            "2:",
            "mov x0, #0", // offset 20: signal = 0 (success)
            "ret",        // offset 24
        )
    }

    pub fn crash_points() -> crate::CrashPoints {
        crate::CrashPoints {
            crash_points: [
                crate::CrashPoint {
                    pc: u64 as *const () as usize,
                    signal_reg: crate::Reg::X1,
                    skip: 8, // skip ldr + mov to land on ret
                },
                crate::CrashPoint {
                    pc: slice as *const () as usize + 4, // +4 for cbz
                    signal_reg: crate::Reg::X0,
                    skip: 20, // skip ldrb + strb + subs + b.ne + mov to land on ret
                },
            ],
        }
    }
}
