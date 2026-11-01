#![no_std]

#[derive(Debug, PartialEq)]
pub struct ReadMemError {
    pub signal: u64,
}

pub type Ptr = u64;

/// Reads a `u64` from `at`, returning `Err` instead of crashing when the
/// address is not readable.
///
/// The load is a single aligned 8-byte access when `at` is aligned. The bytes
/// are returned as-is, whatever the memory contains.
///
/// # Safety
/// `kindasafe_init::init()` must have returned `Ok` in this process and the
/// SIGSEGV/SIGBUS handlers it installed must still be in place. Otherwise a
/// fault terminates the process instead of returning `Err`.
///
/// The read is a plain, non-atomic load and recovery only covers faults. Other
/// threads may be writing `at` concurrently, so the result can be stale or
/// torn and must be treated as untrusted bytes.
///
/// `at` must not refer to memory that Rust code in this program holds a live
/// `&mut` or other exclusive borrow to, unless the address was derived from
/// that borrow and exposed.
pub unsafe fn u64(at: Ptr) -> Result<Ptr, ReadMemError> {
    let res = arch::u64(at);
    if res.signal == 0 {
        Ok(res.value)
    } else {
        Err(ReadMemError { signal: res.signal })
    }
}

/// Copies `buf.len()` bytes from `at` into `buf`, returning `Err` instead of
/// crashing when any source byte is not readable.
///
/// Only faults on the source are reported. `buf` is a valid exclusive slice,
/// so writes into it are always in bounds. On `Err` the contents of `buf` are
/// unspecified.
///
/// # Safety
/// `kindasafe_init::init()` must have returned `Ok` in this process and the
/// SIGSEGV/SIGBUS handlers it installed must still be in place. Otherwise a
/// fault terminates the process instead of returning `Err`.
///
/// The copy is byte-wise and not atomic as a whole. Other threads may be
/// writing the source concurrently, so the result can be stale or torn and
/// must be treated as untrusted bytes.
///
/// `at..at + buf.len()` must not overlap memory that Rust code in this program
/// holds a live `&mut` or other exclusive borrow to, unless the address was
/// derived from that borrow and exposed.
pub unsafe fn slice(buf: &mut [u8], at: Ptr) -> Result<(), ReadMemError> {
    let res = arch::slice(buf.as_mut_ptr(), at, buf.len() as u64);
    if res.signal == 0 {
        Ok(())
    } else {
        Err(ReadMemError { signal: res.signal })
    }
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
mod arch {

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
                    pc: slice as *const () as usize + 3, // +3 for 48 89 D1 	mov 	rcx, rdx
                    signal_reg: crate::Reg::Rax,
                    skip: 4,
                },
            ],
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {

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
                    pc: slice as *const () as usize + 4, // +4 for cbz
                    signal_reg: crate::Reg::X0,
                    skip: 20, // skip ldrb + strb + subs + b.ne + mov to land on ret
                },
            ],
        }
    }
}
