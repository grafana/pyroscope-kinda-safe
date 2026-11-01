//! Signal-safe memory reads with synchronous-fault recovery.
//!
//! A read that touches inaccessible memory recovers only when all of these
//! preconditions hold at the moment of the fault:
//!
//! 1. [`kindasafe_init::init`](https://docs.rs/kindasafe_init/latest/kindasafe_init/fn.init.html)
//!    has completed successfully in this process.
//! 2. SIGSEGV and SIGBUS still resolve to kindasafe's recovery handlers. A
//!    later `sigaction` call by another component can replace them.
//! 3. The thread performing the read has both SIGSEGV and SIGBUS unblocked. A
//!    blocked synchronous fault cannot be recovered by a signal handler; on
//!    Linux the process is normally terminated by the default action instead.
//!
//! The mask is per-thread and is inherited by nested signal handlers. If a
//! profiling signal interrupts an application handler that blocked SIGSEGV or
//! SIGBUS, a `kindasafe` read in the profiling callback has the same blocked
//! mask and cannot recover. Integrations should call
//! [`kindasafe_init::recovery_available`](https://docs.rs/kindasafe_init/latest/kindasafe_init/fn.recovery_available.html)
//! at the start of each sample and skip the read on error. Do not unblock fault
//! signals from inside a profiling handler: that changes the application's
//! signal semantics.
//!
//! This crate intentionally cannot enforce these preconditions automatically.
//! Checking the platform signal mask on every read would add a syscall to a
//! hot primitive, and the crate cannot know which fault signal a particular
//! access will raise without first attempting the access. The
//! `kindasafe_init::recovery_available` guard performs the check once at the
//! integration boundary without modifying any signal state.

#![no_std]

#[derive(Debug, PartialEq)]
pub struct ReadMemError {
    pub signal: u64,
}

pub type Ptr = u64;

/// Reads a `u64` from `at`, recovering from an inaccessible-address fault.
///
/// Fault recovery is only possible when the current thread has working,
/// unblocked SIGSEGV and SIGBUS recovery handlers installed. See the crate
/// documentation for the full precondition list and integration guidance.
pub fn u64(at: Ptr) -> Result<Ptr, ReadMemError> {
    let res = arch::u64(at);
    if res.signal == 0 {
        Ok(res.value)
    } else {
        Err(ReadMemError { signal: res.signal })
    }
}

/// Copies bytes from `at` into `buf`, recovering from an inaccessible source
/// address.
///
/// Fault recovery is only possible when the current thread has working,
/// unblocked SIGSEGV and SIGBUS recovery handlers installed. See the crate
/// documentation for the full precondition list and integration guidance.
/// This does not establish that `at`, aliasing, or concurrent mutation is
/// otherwise valid for the requested range.
pub fn slice(buf: &mut [u8], at: Ptr) -> Result<(), ReadMemError> {
    let res = arch::slice(buf.as_ptr(), at, buf.len() as u64);
    if res.signal == 0 {
        Ok(())
    } else {
        Err(ReadMemError { signal: res.signal })
    }
}

/// Reads a NUL-terminated UTF-8 string from `at` into `buf`.
///
/// Recovery follows the same signal preconditions as [`slice()`]. A missing
/// terminator or invalid UTF-8 is reported as a [`ReadMemError`] with a
/// non-signal status code.
pub fn str(buf: &mut [u8], at: Ptr) -> Result<&str, ReadMemError> {
    if at == 0 {
        return Ok("");
    }
    let res = arch::slice(buf.as_ptr(), at, buf.len() as u64);
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

    #[unsafe(naked)]
    pub extern "sysv64" fn u64(_at: u64) -> U64Res {
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

    #[unsafe(naked)]
    pub extern "sysv64" fn slice(
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

    #[unsafe(naked)]
    pub extern "C" fn u64(_at: u64) -> U64Res {
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

    #[unsafe(naked)]
    pub extern "C" fn slice(
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
