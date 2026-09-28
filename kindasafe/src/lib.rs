#![no_std]

#[derive(Debug, PartialEq)]
pub struct ReadMemError {
    pub signal: u64,
}

pub type Ptr = u64;

pub fn u64(at: Ptr) -> Result<Ptr, ReadMemError> {
    let res = arch::u64(at);
    if res.signal == 0 {
        Ok(res.value)
    } else {
        Err(ReadMemError { signal: res.signal })
    }
}

pub fn slice(buf: &mut [u8], at: Ptr) -> Result<(), ReadMemError> {
    let res = arch::slice(buf.as_ptr(), at, buf.len() as u64);
    if res.signal == 0 {
        Ok(())
    } else {
        Err(ReadMemError { signal: res.signal })
    }
}

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

// Called from the signal handler, which can run on a small sigaltstack: look the pc up
// without materializing the CrashPoints array.
pub fn crash_point(pc: usize) -> Option<CrashPoint> {
    arch::crash_point(pc)
}

#[derive(Copy, Clone)]
pub struct CrashPoint {
    pub pc: usize,
    pub signal_reg: Reg,
    pub skip: usize,
}
#[derive(Copy, Clone)]
pub struct CrashPoints {
    pub crash_points: [CrashPoint; arch::CRASH_POINTS_COUNT],
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
    pub const CRASH_POINTS_COUNT: usize = 1 + SLICE_LOADS.len();

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

    // x86 instructions vary in length, so these are byte offsets read back from the
    // assembled function; the crash_points_are_loads test fails if they drift.
    const SLICE_LOADS: [usize; 28] = [
        24, 46, 54, 61, 76, 80, 97, 103, 122, 128, 147, 150, 161, 166, 193, 196, 200, 204, 223,
        228, 233, 238, 266, 269, 315, 319, 342, 346,
    ];
    const SLICE_RET: usize = 362;

    // LLVM libc inline_memcpy (llvm-project e7dc4d6, Apache-2.0 WITH LLVM-exception) as compiled
    // for x86-64 SSE2, plus crash points and the returned signal.
    #[unsafe(naked)]
    pub extern "sysv64" fn slice(
        _dst: *const u8, // rdi
        _src: u64,       // rsi
        _n: u64,         // rdx
    ) -> VecResult {
        core::arch::naked_asm!(
            "cmp rdx, 1",
            "jle 1f",
            "cmp rdx, 2",
            "je 2f",
            "cmp rdx, 3",
            "je 3f",
            "cmp rdx, 4",
            "jne 4f",
            "mov eax, dword ptr [rsi]", // load
            "mov dword ptr [rdi], eax",
            "xor eax, eax",
            "ret",
            "1:",
            "test rdx, rdx",
            "je 9f",
            "cmp rdx, 1",
            "jne 4f",
            "movzx eax, byte ptr [rsi]", // load
            "mov byte ptr [rdi], al",
            "xor eax, eax",
            "ret",
            "3:",
            "movzx eax, byte ptr [rsi + 2]", // load
            "mov byte ptr [rdi + 2], al",
            "2:",
            "movzx eax, word ptr [rsi]", // load
            "mov word ptr [rdi], ax",
            "xor eax, eax",
            "ret",
            "4:",
            "cmp rdx, 7",
            "ja 5f",
            "mov eax, dword ptr [rsi]", // load
            "mov dword ptr [rdi], eax",
            "mov eax, dword ptr [rsi + rdx - 4]", // load
            "mov dword ptr [rdi + rdx - 4], eax",
            "xor eax, eax",
            "ret",
            "5:",
            "cmp rdx, 15",
            "ja 6f",
            "mov rax, qword ptr [rsi]", // load
            "mov qword ptr [rdi], rax",
            "mov rax, qword ptr [rsi + rdx - 8]", // load
            "mov qword ptr [rdi + rdx - 8], rax",
            "xor eax, eax",
            "ret",
            "6:",
            "cmp rdx, 32",
            "ja 7f",
            "movups xmm0, xmmword ptr [rsi]", // load
            "movups xmmword ptr [rdi], xmm0",
            "movups xmm0, xmmword ptr [rsi + rdx - 16]", // load
            "movups xmmword ptr [rdi + rdx - 16], xmm0",
            "xor eax, eax",
            "ret",
            "7:",
            "cmp rdx, 64",
            "ja 8f",
            "movups xmm0, xmmword ptr [rsi]",      // load
            "movups xmm1, xmmword ptr [rsi + 16]", // load
            "movups xmmword ptr [rdi + 16], xmm1",
            "movups xmmword ptr [rdi], xmm0",
            "movups xmm0, xmmword ptr [rsi + rdx - 32]", // load
            "movups xmm1, xmmword ptr [rsi + rdx - 16]", // load
            "movups xmmword ptr [rdi + rdx - 16], xmm1",
            "movups xmmword ptr [rdi + rdx - 32], xmm0",
            "xor eax, eax",
            "ret",
            "8:",
            "cmp rdx, 128",
            "ja 10f",
            "movups xmm0, xmmword ptr [rsi]",      // load
            "movups xmm1, xmmword ptr [rsi + 16]", // load
            "movups xmm2, xmmword ptr [rsi + 32]", // load
            "movups xmm3, xmmword ptr [rsi + 48]", // load
            "movups xmmword ptr [rdi + 48], xmm3",
            "movups xmmword ptr [rdi + 32], xmm2",
            "movups xmmword ptr [rdi + 16], xmm1",
            "movups xmmword ptr [rdi], xmm0",
            "movups xmm0, xmmword ptr [rsi + rdx - 64]", // load
            "movups xmm1, xmmword ptr [rsi + rdx - 48]", // load
            "movups xmm2, xmmword ptr [rsi + rdx - 32]", // load
            "movups xmm3, xmmword ptr [rsi + rdx - 16]", // load
            "movups xmmword ptr [rdi + rdx - 16], xmm3",
            "movups xmmword ptr [rdi + rdx - 32], xmm2",
            "movups xmmword ptr [rdi + rdx - 48], xmm1",
            "movups xmmword ptr [rdi + rdx - 64], xmm0",
            "xor eax, eax",
            "ret",
            "10:",
            "movups xmm0, xmmword ptr [rsi]",      // load
            "movups xmm1, xmmword ptr [rsi + 16]", // load
            "movups xmmword ptr [rdi + 16], xmm1",
            "movups xmmword ptr [rdi], xmm0",
            "mov eax, edi",
            "and eax, 31",
            "mov ecx, 32",
            "sub rcx, rax",
            "neg rax",
            "add rax, rdi",
            "add rax, 32",
            "add rsi, rcx",
            "sub rdx, rcx",
            "add rdx, -32",
            "xor ecx, ecx",
            "11:",
            "movups xmm0, xmmword ptr [rsi + rcx]", // load
            "movups xmm1, xmmword ptr [rsi + rcx + 16]", // load
            "movups xmmword ptr [rax + rcx + 16], xmm1",
            "movups xmmword ptr [rax + rcx], xmm0",
            "add rcx, 32",
            "cmp rcx, rdx",
            "jb 11b",
            "movups xmm0, xmmword ptr [rsi + rdx]", // load
            "movups xmm1, xmmword ptr [rsi + rdx + 16]", // load
            "movups xmmword ptr [rax + rdx + 16], xmm1",
            "movups xmmword ptr [rax + rdx], xmm0",
            "9:",
            "xor eax, eax",
            "ret",
        )
    }

    pub fn crash_point(pc: usize) -> Option<crate::CrashPoint> {
        if pc == u64 as *const () as usize {
            return Some(crate::CrashPoint {
                pc,
                signal_reg: crate::Reg::Rdx,
                skip: 5,
            });
        }
        let load = pc.checked_sub(slice as *const () as usize)?;
        SLICE_LOADS.contains(&load).then_some(crate::CrashPoint {
            pc,
            signal_reg: crate::Reg::Rax,
            skip: SLICE_RET - load,
        })
    }

    pub fn crash_points() -> crate::CrashPoints {
        let u64_point = crate::CrashPoint {
            pc: u64 as *const () as usize,
            signal_reg: crate::Reg::Rdx,
            skip: 5,
        };
        let mut crash_points = [u64_point; CRASH_POINTS_COUNT];
        let base = slice as *const () as usize;
        for (point, &load) in crash_points[1..].iter_mut().zip(SLICE_LOADS.iter()) {
            *point = crate::CrashPoint {
                pc: base + load,
                signal_reg: crate::Reg::Rax,
                skip: SLICE_RET - load,
            };
        }
        crate::CrashPoints { crash_points }
    }
}

#[cfg(target_arch = "aarch64")]
pub mod arch {
    pub const CRASH_POINTS_COUNT: usize = 1 + SLICE_LOADS.len();

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

    // Every instruction is 4 bytes, so the crash points below are instruction
    // indices; SLICE_LOADS and SLICE_RET must be updated with any edit to the asm.
    const SLICE_LOADS: [usize; 22] = [
        8, 15, 19, 23, 24, 31, 33, 40, 42, 49, 51, 58, 63, 69, 74, 76, 78, 84, 95, 98, 103, 105,
    ];
    const SLICE_RET: usize = 108;

    // LLVM libc inline_memcpy (llvm-project e7dc4d6, Apache-2.0 WITH LLVM-exception) as compiled
    // for aarch64, plus crash points and the returned signal.
    #[unsafe(naked)]
    pub extern "C" fn slice(
        _dst: *const u8, // x0
        _src: u64,       // x1
        _n: u64,         // x2
    ) -> VecResult {
        core::arch::naked_asm!(
            "cmp x2, #1",   // 0
            "b.le 1f",      // 1
            "cmp x2, #2",   // 2
            "b.eq 2f",      // 3
            "cmp x2, #3",   // 4
            "b.eq 3f",      // 5
            "cmp x2, #4",   // 6
            "b.ne 4f",      // 7
            "ldr w8, [x1]", // 8: load
            "str w8, [x0]", // 9
            "mov x0, #0",   // 10
            "ret",          // 11
            "1:",
            "cbz x2, 9f",    // 12
            "cmp x2, #1",    // 13
            "b.ne 4f",       // 14
            "ldrb w8, [x1]", // 15: load
            "strb w8, [x0]", // 16
            "mov x0, #0",    // 17
            "ret",           // 18
            "2:",
            "ldrh w8, [x1]", // 19: load
            "strh w8, [x0]", // 20
            "mov x0, #0",    // 21
            "ret",           // 22
            "3:",
            "ldrh w8, [x1]",     // 23: load
            "ldrb w9, [x1, #2]", // 24: load
            "strh w8, [x0]",     // 25
            "strb w9, [x0, #2]", // 26
            "mov x0, #0",        // 27
            "ret",               // 28
            "4:",
            "cmp x2, #7",        // 29
            "b.hi 5f",           // 30
            "ldr w8, [x1]",      // 31: load
            "sub x9, x2, #4",    // 32
            "ldr w10, [x1, x9]", // 33: load
            "str w8, [x0]",      // 34
            "str w10, [x0, x9]", // 35
            "mov x0, #0",        // 36
            "ret",               // 37
            "5:",
            "cmp x2, #15",       // 38
            "b.hi 6f",           // 39
            "ldr x8, [x1]",      // 40: load
            "sub x9, x2, #8",    // 41
            "ldr x10, [x1, x9]", // 42: load
            "str x8, [x0]",      // 43
            "str x10, [x0, x9]", // 44
            "mov x0, #0",        // 45
            "ret",               // 46
            "6:",
            "cmp x2, #31",      // 47
            "b.hi 7f",          // 48
            "ldr q0, [x1]",     // 49: load
            "sub x8, x2, #16",  // 50
            "ldr q1, [x1, x8]", // 51: load
            "str q0, [x0]",     // 52
            "str q1, [x0, x8]", // 53
            "mov x0, #0",       // 54
            "ret",              // 55
            "7:",
            "cmp x2, #63",      // 56
            "b.hi 8f",          // 57
            "ldp q0, q1, [x1]", // 58: load
            "sub x8, x2, #32",  // 59
            "add x9, x1, x8",   // 60
            "add x8, x0, x8",   // 61
            "stp q0, q1, [x0]", // 62
            "ldp q0, q1, [x9]", // 63: load
            "stp q0, q1, [x8]", // 64
            "mov x0, #0",       // 65
            "ret",              // 66
            "8:",
            "cmp x2, #127",          // 67
            "b.hi 10f",              // 68
            "ldp q0, q1, [x1]",      // 69: load
            "sub x8, x2, #64",       // 70
            "add x9, x1, x8",        // 71
            "add x8, x0, x8",        // 72
            "stp q0, q1, [x0]",      // 73
            "ldp q0, q2, [x1, #32]", // 74: load
            "stp q0, q2, [x0, #32]", // 75
            "ldp q0, q1, [x9]",      // 76: load
            "stp q0, q1, [x8]",      // 77
            "ldp q2, q0, [x9, #32]", // 78: load
            "stp q2, q0, [x8, #32]", // 79
            "mov x0, #0",            // 80
            "ret",                   // 81
            "10:",
            "and x9, x1, #0xf",  // 82
            "mov w10, #16",      // 83
            "ldr q0, [x1]",      // 84: load
            "sub x9, x10, x9",   // 85
            "mov x8, xzr",       // 86
            "sub x11, x2, x9",   // 87
            "add x10, x1, x9",   // 88
            "add x9, x0, x9",    // 89
            "sub x11, x11, #64", // 90
            "str q0, [x0]",      // 91
            "11:",
            "add x12, x10, x8",       // 92
            "add x13, x9, x8",        // 93
            "add x8, x8, #64",        // 94
            "ldp q0, q1, [x12]",      // 95: load
            "cmp x8, x11",            // 96
            "stp q0, q1, [x13]",      // 97
            "ldp q2, q0, [x12, #32]", // 98: load
            "stp q2, q0, [x13, #32]", // 99
            "b.lo 11b",               // 100
            "add x8, x10, x11",       // 101
            "add x9, x9, x11",        // 102
            "ldp q0, q1, [x8]",       // 103: load
            "stp q0, q1, [x9]",       // 104
            "ldp q0, q2, [x8, #32]",  // 105: load
            "stp q0, q2, [x9, #32]",  // 106
            "9:",
            "mov x0, #0", // 107
            "ret",        // 108
        )
    }

    pub fn crash_point(pc: usize) -> Option<crate::CrashPoint> {
        if pc == u64 as *const () as usize {
            return Some(crate::CrashPoint {
                pc,
                signal_reg: crate::Reg::X1,
                skip: 8,
            });
        }
        let off = pc.checked_sub(slice as *const () as usize)?;
        if off % 4 != 0 {
            return None;
        }
        let load = off / 4;
        SLICE_LOADS.contains(&load).then_some(crate::CrashPoint {
            pc,
            signal_reg: crate::Reg::X0,
            skip: (SLICE_RET - load) * 4,
        })
    }

    pub fn crash_points() -> crate::CrashPoints {
        let u64_point = crate::CrashPoint {
            pc: u64 as *const () as usize,
            signal_reg: crate::Reg::X1,
            skip: 8, // skip ldr + mov to land on ret
        };
        let mut crash_points = [u64_point; CRASH_POINTS_COUNT];
        let base = slice as *const () as usize;
        for (point, &load) in crash_points[1..].iter_mut().zip(SLICE_LOADS.iter()) {
            *point = crate::CrashPoint {
                pc: base + load * 4,
                signal_reg: crate::Reg::X0,
                skip: (SLICE_RET - load) * 4,
            };
        }
        crate::CrashPoints { crash_points }
    }
}
