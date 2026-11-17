#![no_std]

//! Fault-recovering memory reads in normal builds and instrumented reads under ASan.
//!
//! # ASan builds
//! Reads use compiler-instrumented Rust loads without assembly or fault recovery.
//! Invalid accesses are left to ASan or fatal-signal handling. For valid reads,
//! the source must contain initialized bytes, obey Rust's pointer and aliasing
//! rules, and remain free of concurrent writes or deallocation during the read.
//! Initialization and recovery sanity checks are unnecessary in this mode.
//!
//! ASan builds are for diagnosing unwinder bugs. An invalid read is a test
//! failure, so we accept ASan's standard fatal reporting even inside SIGPROF.
//! That reporting is not guaranteed async-signal-safe: it can deadlock if the
//! interrupted thread holds a lock the reporter needs. Diagnostics are therefore
//! best-effort, and fault tests use subprocess timeouts. This tradeoff is limited
//! to ASan builds; normal builds recover faults without invoking ASan.

#[cfg(not(kindasafe_asan))]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(kindasafe_asan))]
static RECOVERED_FAULTS: AtomicU64 = AtomicU64::new(0);

/// Cumulative number of public reads that returned a recovered fault.
///
/// A failed slice counts once, regardless of how many bytes were copied.
/// Sanity checks and signals forwarded to other handlers are excluded.
/// The counter uses relaxed, lock-free atomics on supported targets, wraps on
/// overflow, and has no reset operation. ASan builds always return zero.
/// The embedding application can export this value through its metrics system.
pub fn recovered_faults() -> u64 {
    #[cfg(not(kindasafe_asan))]
    {
        RECOVERED_FAULTS.load(Ordering::Relaxed)
    }
    #[cfg(kindasafe_asan)]
    {
        0
    }
}

#[cfg(not(kindasafe_asan))]
fn recovered_error(signal: u64) -> ReadMemError {
    RECOVERED_FAULTS.fetch_add(1, Ordering::Relaxed);
    ReadMemError { signal }
}

#[derive(Debug, PartialEq)]
pub struct ReadMemError {
    pub signal: u64,
}

pub type Ptr = u64;

/// Reads a `u64` from `at`, returning `Err` instead of crashing when the
/// address is not readable.
///
/// In normal builds, reads eight bytes using a single load instruction. The
/// address may be unaligned. The bytes are returned as-is.
///
/// In ASan builds, accesses use compiler instrumentation and do not recover.
///
/// # Safety
/// Under ASan, the [crate-level source-memory requirements](crate) apply.
/// The following recovery and concurrent-access rules apply to normal builds.
///
/// `kindasafe_init::init()` must have returned `Ok` in this process and the
/// SIGSEGV/SIGBUS handlers it installed must still be in place. Otherwise a
/// fault terminates the process instead of returning `Err`.
/// SIGSEGV and SIGBUS must also be unblocked on the calling thread.
///
/// The read is a plain, non-atomic load and recovery only covers faults. Other
/// threads may be writing `at` concurrently, so the result can be stale or
/// torn and must be treated as untrusted bytes.
///
/// `at` must not refer to memory that Rust code in this program holds a live
/// `&mut` or other exclusive borrow to, unless the address was derived from
/// that borrow and exposed.
#[inline(always)]
pub unsafe fn u64(at: Ptr) -> Result<Ptr, ReadMemError> {
    #[cfg(kindasafe_asan)]
    {
        // SAFETY: the caller satisfies the ASan source-memory requirements.
        Ok(unsafe { (at as *const u64).read_unaligned() })
    }
    #[cfg(not(kindasafe_asan))]
    {
        let res = arch::u64(at);
        if res.signal == 0 {
            Ok(res.value)
        } else {
            Err(recovered_error(res.signal))
        }
    }
}

/// Checks recovery using address 239 without incrementing [`recovered_faults`].
///
/// In normal builds the recovery handlers must already be installed and
/// SIGSEGV/SIGBUS unblocked. ASan builds return `true` without attempting a read.
pub fn sanity_check() -> bool {
    #[cfg(not(kindasafe_asan))]
    {
        arch::u64(239).signal != 0
    }
    #[cfg(kindasafe_asan)]
    {
        true
    }
}

/// Reads a `u32` from `at`, returning `Err` instead of crashing when the
/// address is not readable.
///
/// In normal builds, reads four bytes using a single load instruction. The
/// address may be unaligned. The bytes are returned as-is.
///
/// In ASan builds, accesses use compiler instrumentation and do not recover.
///
/// # Safety
/// Under ASan, the [crate-level source-memory requirements](crate) apply.
/// The following recovery and concurrent-access rules apply to normal builds.
///
/// `kindasafe_init::init()` must have returned `Ok` in this process and the
/// SIGSEGV/SIGBUS handlers it installed must still be in place. Otherwise a
/// fault terminates the process instead of returning `Err`.
/// SIGSEGV and SIGBUS must also be unblocked on the calling thread.
///
/// The read is a plain, non-atomic load and recovery only covers faults. Other
/// threads may be writing `at` concurrently, so the result can be stale or
/// torn and must be treated as untrusted bytes.
///
/// `at` must not refer to memory that Rust code in this program holds a live
/// `&mut` or other exclusive borrow to, unless the address was derived from
/// that borrow and exposed.
#[inline(always)]
pub unsafe fn u32(at: Ptr) -> Result<u32, ReadMemError> {
    #[cfg(kindasafe_asan)]
    {
        // SAFETY: the caller satisfies the ASan source-memory requirements.
        Ok(unsafe { (at as *const u32).read_unaligned() })
    }
    #[cfg(not(kindasafe_asan))]
    {
        let res = arch::u32(at);
        if res.signal == 0 {
            Ok(res.value as u32)
        } else {
            Err(recovered_error(res.signal))
        }
    }
}

/// Reads a `u8` from `at`, returning `Err` instead of crashing when the
/// address is not readable.
///
/// The load reads exactly one byte, returned as-is, whatever the memory contains.
///
/// In ASan builds, accesses use compiler instrumentation and do not recover.
///
/// # Safety
/// Under ASan, the [crate-level source-memory requirements](crate) apply.
/// The following recovery and concurrent-access rules apply to normal builds.
///
/// `kindasafe_init::init()` must have returned `Ok` in this process and the
/// SIGSEGV/SIGBUS handlers it installed must still be in place. Otherwise a
/// fault terminates the process instead of returning `Err`.
/// SIGSEGV and SIGBUS must also be unblocked on the calling thread.
///
/// The read is a plain, non-atomic load and recovery only covers faults. Other
/// threads may be writing `at` concurrently, so the result can be stale
/// and must be treated as untrusted data.
///
/// `at` must not refer to memory that Rust code in this program holds a live
/// `&mut` or other exclusive borrow to, unless the address was derived from
/// that borrow and exposed.
#[inline(always)]
pub unsafe fn u8(at: Ptr) -> Result<u8, ReadMemError> {
    #[cfg(kindasafe_asan)]
    {
        // SAFETY: the caller satisfies the ASan source-memory requirements.
        Ok(unsafe { (at as *const u8).read_unaligned() })
    }
    #[cfg(not(kindasafe_asan))]
    {
        let res = arch::u8(at);
        if res.signal == 0 {
            Ok(res.value as u8)
        } else {
            Err(recovered_error(res.signal))
        }
    }
}

/// Copies `buf.len()` bytes from `at` into `buf`, returning `Err` instead of
/// crashing when any source byte is not readable.
///
/// Only faults on the source are reported. `buf` is a valid exclusive slice,
/// so writes into it are always in bounds. On `Err` the contents of `buf` are
/// unspecified.
///
/// In ASan builds, accesses use compiler instrumentation and do not recover.
///
/// # Safety
/// Under ASan, the [crate-level source-memory requirements](crate) apply.
/// The following recovery and concurrent-access rules apply to normal builds.
///
/// `kindasafe_init::init()` must have returned `Ok` in this process and the
/// SIGSEGV/SIGBUS handlers it installed must still be in place. Otherwise a
/// fault terminates the process instead of returning `Err`.
/// SIGSEGV and SIGBUS must also be unblocked on the calling thread.
///
/// The copy is byte-wise and not atomic as a whole. Other threads may be
/// writing the source concurrently, so the result can be stale or torn and
/// must be treated as untrusted bytes.
///
/// `at..at + buf.len()` must not overlap memory that Rust code in this program
/// holds a live `&mut` or other exclusive borrow to, unless the address was
/// derived from that borrow and exposed.
pub unsafe fn slice(buf: &mut [u8], at: Ptr) -> Result<(), ReadMemError> {
    #[cfg(kindasafe_asan)]
    {
        // An empty copy must not access even a null or poisoned source.
        let src = at as *const u8;
        let dst = buf.as_mut_ptr();
        for i in 0..buf.len() {
            // SAFETY: the caller provides a valid source; dst is within buf.
            unsafe { dst.add(i).write(src.add(i).read()) };
        }
        Ok(())
    }
    #[cfg(not(kindasafe_asan))]
    {
        let res = arch::slice(buf.as_mut_ptr(), at, buf.len() as u64);
        if res.signal == 0 {
            Ok(())
        } else {
            Err(recovered_error(res.signal))
        }
    }
}

/// Recovery locations, or an empty table in ASan builds.
pub fn crash_points() -> CrashPoints {
    #[cfg(not(kindasafe_asan))]
    {
        arch::crash_points()
    }
    #[cfg(kindasafe_asan)]
    {
        CrashPoints { crash_points: [] }
    }
}

#[derive(Copy, Clone)]
pub struct CrashPoint {
    pub pc: usize,
    pub signal_reg: Reg,
    pub skip: usize,
}
#[cfg(not(kindasafe_asan))]
const CRASH_POINTS_COUNT: usize = 4;
#[cfg(kindasafe_asan)]
const CRASH_POINTS_COUNT: usize = 0;

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

#[cfg(all(not(kindasafe_asan), target_arch = "x86_64"))]
mod arch {

    #[repr(C)]
    pub struct ScalarResult {
        pub value: u64,
        pub signal: u64,
    }

    #[unsafe(naked)]
    pub extern "sysv64" fn u64(_at: u64) -> ScalarResult {
        core::arch::naked_asm!(
            "mov rax, [rdi]", // 00010000 	48 8B 07 	mov 	rax, qword ptr [rdi]
            "xor edx, edx",   // 00010003 	31 D2 	xor 	edx, edx
            "ret",            // 00010005 	C3 	ret
        )
    }

    #[unsafe(naked)]
    pub extern "sysv64" fn u32(_at: u64) -> ScalarResult {
        core::arch::naked_asm!(
            "mov eax, [rdi]", // offset 0: load 32 bits, zero-extending into rax
            "xor edx, edx",   // offset 2: signal = 0 (success)
            "ret",            // offset 4
        )
    }

    #[unsafe(naked)]
    pub extern "sysv64" fn u8(_at: u64) -> ScalarResult {
        core::arch::naked_asm!(
            "movzx eax, byte ptr [rdi]", // offset 0: load 8 bits, zero-extending into rax
            "xor edx, edx",              // offset 3: signal = 0 (success)
            "ret",                       // offset 5
        )
    }

    #[repr(C)]
    pub struct VecResult {
        pub signal: u64,
    }

    #[unsafe(naked)]
    pub extern "sysv64" fn slice(
        _dst: *mut u8, // rdi
        _src: u64,     // rsi
        _n: u64,       // rdx
    ) -> VecResult {
        core::arch::naked_asm!(
            "mov rcx, rdx", // 00010000 	48 89 D1 	mov 	rcx, rdx
            "rep movsb",    // 00010003 	F3 A4 	rep movsb 	byte ptr [rdi], byte ptr [rsi]
            "xor eax, eax", // 00010005 	31 C0 	xor 	eax, eax
            "ret",          // 00010007 	C3 	ret
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
                    pc: u32 as *const () as usize,
                    signal_reg: crate::Reg::Rdx,
                    skip: 4,
                },
                crate::CrashPoint {
                    pc: u8 as *const () as usize,
                    signal_reg: crate::Reg::Rdx,
                    skip: 5,
                },
                crate::CrashPoint {
                    pc: slice as *const () as usize + 3, // +3 for 48 89 D1 	mov 	rcx, rdx
                    signal_reg: crate::Reg::Rax,
                    skip: 4,
                },
            ],
        }
    }
}

#[cfg(all(not(kindasafe_asan), target_arch = "aarch64"))]
mod arch {

    #[repr(C)]
    pub struct ScalarResult {
        pub value: u64,
        pub signal: u64,
    }

    #[unsafe(naked)]
    pub extern "C" fn u64(_at: u64) -> ScalarResult {
        core::arch::naked_asm!(
            "ldr x0, [x0]", // offset 0: load 64-bit value from address in x0
            "mov x1, #0",   // offset 4: signal = 0 (success)
            "ret",          // offset 8
        )
    }

    #[unsafe(naked)]
    pub extern "C" fn u32(_at: u64) -> ScalarResult {
        core::arch::naked_asm!(
            "ldr w0, [x0]", // offset 0: load 32 bits, zero-extending into x0
            "mov x1, #0",   // offset 4: signal = 0 (success)
            "ret",          // offset 8
        )
    }

    #[unsafe(naked)]
    pub extern "C" fn u8(_at: u64) -> ScalarResult {
        core::arch::naked_asm!(
            "ldrb w0, [x0]", // offset 0: load 8 bits, zero-extending into x0
            "mov x1, #0",    // offset 4: signal = 0 (success)
            "ret",           // offset 8
        )
    }

    #[repr(C)]
    pub struct VecResult {
        pub signal: u64,
    }

    #[unsafe(naked)]
    pub extern "C" fn slice(
        _dst: *mut u8, // x0
        _src: u64,     // x1
        _n: u64,       // x2
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
                    pc: u32 as *const () as usize,
                    signal_reg: crate::Reg::X1,
                    skip: 8,
                },
                crate::CrashPoint {
                    pc: u8 as *const () as usize,
                    signal_reg: crate::Reg::X1,
                    skip: 8,
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
