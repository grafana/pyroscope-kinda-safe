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
    const SLICE_LOADS: [usize; 33] = [
        6, 15, 46, 50, 65, 69, 80, 85, 99, 104, 138, 148, 152, 156, 161, 166, 171, 251, 256, 268,
        273, 293, 296, 300, 304, 367, 371, 380, 384, 400, 404, 408, 412,
    ];
    const SLICE_RET: usize = 467;

    // Instruction-for-instruction the forward paths of glibc __memmove_sse2_unaligned,
    // minus its non-temporal branch, plus crash points.
    #[unsafe(naked)]
    pub extern "sysv64" fn slice(
        _dst: *const u8, // rdi
        _src: u64,       // rsi
        _n: u64,         // rdx
    ) -> VecResult {
        core::arch::naked_asm!(
            "cmp rdx, 16",
            "jb 20f",
            "movups xmm0, xmmword ptr [rsi]", // load
            "cmp rdx, 32",
            "ja 30f",
            "movups xmm1, xmmword ptr [rsi + rdx - 16]", // load, 16..=32
            "movups xmmword ptr [rdi], xmm0",
            "movups xmmword ptr [rdi + rdx - 16], xmm1",
            "xor eax, eax",
            "ret",
            "20:",
            "cmp edx, 8",
            "jae 23f",
            "cmp edx, 4",
            "jae 22f",
            "cmp edx, 1",
            "jl 29f",
            "mov cl, byte ptr [rsi]", // load, 1..=3
            "je 21f",
            "movzx esi, word ptr [rsi + rdx - 2]", // load
            "mov word ptr [rdi + rdx - 2], si",
            "21:",
            "mov byte ptr [rdi], cl",
            "29:",
            "xor eax, eax",
            "ret",
            "22:",
            "mov ecx, dword ptr [rsi + rdx - 4]", // load, 4..=7
            "mov esi, dword ptr [rsi]",           // load
            "mov dword ptr [rdi + rdx - 4], ecx",
            "mov dword ptr [rdi], esi",
            "xor eax, eax",
            "ret",
            "23:",
            "mov rcx, qword ptr [rsi + rdx - 8]", // load, 8..=15
            "mov rsi, qword ptr [rsi]",           // load
            "mov qword ptr [rdi], rsi",
            "mov qword ptr [rdi + rdx - 8], rcx",
            "xor eax, eax",
            "ret",
            "31:",
            "movups xmm2, xmmword ptr [rsi + rdx - 16]", // load, 33..=64
            "movups xmm3, xmmword ptr [rsi + rdx - 32]", // load
            "movups xmmword ptr [rdi], xmm0",
            "movups xmmword ptr [rdi + 16], xmm1",
            "movups xmmword ptr [rdi + rdx - 16], xmm2",
            "movups xmmword ptr [rdi + rdx - 32], xmm3",
            "xor eax, eax",
            "ret",
            "30:",
            "cmp rdx, 128",
            "ja 40f",
            "movups xmm1, xmmword ptr [rsi + 16]", // load, 33..=128
            "cmp rdx, 64",
            "jbe 31b",
            "movups xmm2, xmmword ptr [rsi + 32]", // load, 65..=128
            "movups xmm3, xmmword ptr [rsi + 48]", // load
            "movups xmm4, xmmword ptr [rsi + rdx - 16]", // load
            "movups xmm5, xmmword ptr [rsi + rdx - 32]", // load
            "movups xmm6, xmmword ptr [rsi + rdx - 48]", // load
            "movups xmm7, xmmword ptr [rsi + rdx - 64]", // load
            "movups xmmword ptr [rdi], xmm0",
            "movups xmmword ptr [rdi + 16], xmm1",
            "movups xmmword ptr [rdi + 32], xmm2",
            "movups xmmword ptr [rdi + 48], xmm3",
            "movups xmmword ptr [rdi + rdx - 16], xmm4",
            "movups xmmword ptr [rdi + rdx - 32], xmm5",
            "movups xmmword ptr [rdi + rdx - 48], xmm6",
            "movups xmmword ptr [rdi + rdx - 64], xmm7",
            "xor eax, eax",
            "ret",
            "40:",
            "mov rcx, rdi", // > 128
            "sub rcx, rsi",
            "cmp rcx, rdx",
            "jb 60f", // dst - src < n: copy backward
            "lea r8, [rcx + rdx]",
            "xor r8, rcx",
            "shr r8, 63",
            "and ecx, 0xf00",
            "add ecx, r8d",
            "je 61f",                                    // 4k aliasing: copy backward
            "movups xmm5, xmmword ptr [rsi + rdx - 16]", // load, forward: last 64 bytes first
            "movups xmm6, xmmword ptr [rsi + rdx - 32]", // load
            "mov rcx, rdi",
            "or rdi, 15",
            "movups xmm7, xmmword ptr [rsi + rdx - 48]", // load
            "movups xmm8, xmmword ptr [rsi + rdx - 64]", // load
            "sub rsi, rcx",
            "inc rdi",
            "add rsi, rdi",
            "lea rdx, [rcx + rdx - 64]",
            "50:",
            "movups xmm1, xmmword ptr [rsi]", // load, 64-byte blocks to 16-aligned dst
            "movups xmm2, xmmword ptr [rsi + 16]", // load
            "movups xmm3, xmmword ptr [rsi + 32]", // load
            "movups xmm4, xmmword ptr [rsi + 48]", // load
            "sub rsi, -64",
            "movaps xmmword ptr [rdi], xmm1",
            "movaps xmmword ptr [rdi + 16], xmm2",
            "movaps xmmword ptr [rdi + 32], xmm3",
            "movaps xmmword ptr [rdi + 48], xmm4",
            "sub rdi, -64",
            "cmp rdx, rdi",
            "ja 50b",
            "movups xmmword ptr [rdx + 48], xmm5",
            "movups xmmword ptr [rdx + 32], xmm6",
            "movups xmmword ptr [rdx + 16], xmm7",
            "movups xmmword ptr [rdx], xmm8",
            "movups xmmword ptr [rcx], xmm0",
            "xor eax, eax",
            "ret",
            "60:",
            "test rcx, rcx",
            "je 29b", // dst == src
            "61:",
            "movups xmm5, xmmword ptr [rsi + 16]", // load, backward: first 64 bytes first
            "movups xmm6, xmmword ptr [rsi + 32]", // load
            "lea rcx, [rdi + rdx - 65]",
            "movups xmm7, xmmword ptr [rsi + 48]",       // load
            "movups xmm8, xmmword ptr [rsi + rdx - 16]", // load
            "sub rsi, rdi",
            "and rcx, -16",
            "add rsi, rcx",
            "62:",
            "movups xmm1, xmmword ptr [rsi + 48]", // load, 64-byte blocks downward
            "movups xmm2, xmmword ptr [rsi + 32]", // load
            "movups xmm3, xmmword ptr [rsi + 16]", // load
            "movups xmm4, xmmword ptr [rsi]",      // load
            "add rsi, -64",
            "movaps xmmword ptr [rcx + 48], xmm1",
            "movaps xmmword ptr [rcx + 32], xmm2",
            "movaps xmmword ptr [rcx + 16], xmm3",
            "movaps xmmword ptr [rcx], xmm4",
            "add rcx, -64",
            "cmp rdi, rcx",
            "jb 62b",
            "movups xmmword ptr [rdi], xmm0",
            "movups xmmword ptr [rdi + 16], xmm5",
            "movups xmmword ptr [rdi + 32], xmm6",
            "movups xmmword ptr [rdi + 48], xmm7",
            "movups xmmword ptr [rdx + rdi - 16], xmm8",
            "xor eax, eax",
            "ret",
            "9:",
            "ret", // fault landing: the handler sets rax to the signal
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
    // Instruction-for-instruction the forward path of macOS _platform_memmove, plus crash points.
    #[cfg(target_os = "macos")]
    const SLICE_LOADS: [usize; 19] = [
        8, 9, 15, 16, 22, 23, 30, 31, 32, 38, 39, 48, 51, 59, 64, 72, 75, 83, 88,
    ];
    #[cfg(target_os = "macos")]
    const SLICE_RET: usize = 95;

    #[cfg(target_os = "macos")]
    #[unsafe(naked)]
    pub extern "C" fn slice(
        _dst: *const u8, // x0
        _src: u64,       // x1
        _n: u64,         // x2
    ) -> VecResult {
        core::arch::naked_asm!(
            "cmp x2, #64",         // 0
            "b.hi 6f",             // 1
            "add x3, x1, x2",      // 2: srcend
            "add x4, x0, x2",      // 3: dstend
            "cmp x2, #32",         // 4
            "b.hi 4f",             // 5
            "cmp x2, #16",         // 6
            "b.lo 1f",             // 7
            "ldr q0, [x1]",        // 8: load, 16..=32
            "ldur q1, [x3, #-16]", // 9: load
            "str q0, [x0]",        // 10
            "stur q1, [x4, #-16]", // 11
            "mov x0, #0",          // 12
            "ret",                 // 13
            "1:",
            "tbz x2, #3, 2f",     // 14
            "ldr x5, [x1]",       // 15: load, 8..=15
            "ldur x6, [x3, #-8]", // 16: load
            "str x5, [x0]",       // 17
            "stur x6, [x4, #-8]", // 18
            "mov x0, #0",         // 19
            "ret",                // 20
            "2:",
            "tbz x2, #2, 3f",     // 21
            "ldr w5, [x1]",       // 22: load, 4..=7
            "ldur w6, [x3, #-4]", // 23: load
            "str w5, [x0]",       // 24
            "stur w6, [x4, #-4]", // 25
            "mov x0, #0",         // 26
            "ret",                // 27
            "3:",
            "cbz x2, 9f",          // 28
            "lsr x7, x2, #1",      // 29
            "ldrb w5, [x1]",       // 30: load, 1..=3
            "ldurb w6, [x3, #-1]", // 31: load
            "ldrb w8, [x1, x7]",   // 32: load
            "strb w5, [x0]",       // 33
            "sturb w6, [x4, #-1]", // 34
            "strb w8, [x0, x7]",   // 35
            "mov x0, #0",          // 36
            "ret",                 // 37
            "4:",
            "ldp q0, q1, [x1]",       // 38: load, 33..=64
            "ldp q2, q3, [x3, #-32]", // 39: load
            "stp q0, q1, [x0]",       // 40
            "stp q2, q3, [x4, #-32]", // 41
            "mov x0, #0",             // 42
            "ret",                    // 43
            "6:",
            "cmp x2, #16384",    // 44
            "b.hs 7f",           // 45
            "add x6, x0, #32",   // 46: dst rounded up to 32
            "and x6, x6, #-32",  // 47
            "ldnp q2, q3, [x1]", // 48: load
            "sub x5, x6, x0",    // 49
            "add x1, x1, x5",    // 50
            "ldnp q0, q1, [x1]", // 51: load
            "add x1, x1, #32",   // 52
            "sub x2, x2, x5",    // 53
            "stp q2, q3, [x0]",  // 54
            "subs x2, x2, #64",  // 55
            "b.ls 11f",          // 56
            "10:",
            "stp q0, q1, [x6]",  // 57: 32-byte blocks to aligned dst
            "add x6, x6, #32",   // 58
            "ldnp q0, q1, [x1]", // 59: load
            "add x1, x1, #32",   // 60
            "subs x2, x2, #32",  // 61
            "b.hi 10b",          // 62
            "11:",
            "add x1, x1, x2",        // 63
            "ldnp q2, q3, [x1]",     // 64: load, last 32 bytes, may overlap
            "stp q0, q1, [x6]",      // 65
            "add x6, x6, x2",        // 66
            "stp q2, q3, [x6, #32]", // 67
            "mov x0, #0",            // 68
            "ret",                   // 69
            "7:",
            "add x6, x0, #32",   // 70: dst rounded up to 32
            "and x6, x6, #-32",  // 71
            "ldnp q2, q3, [x1]", // 72: load
            "sub x5, x6, x0",    // 73
            "add x1, x1, x5",    // 74
            "ldnp q0, q1, [x1]", // 75: load
            "add x1, x1, #32",   // 76
            "sub x2, x2, x5",    // 77
            "stnp q2, q3, [x0]", // 78
            "subs x2, x2, #64",  // 79
            "b.ls 13f",          // 80
            "12:",
            "stnp q0, q1, [x6]", // 81: 32-byte blocks to aligned dst
            "add x6, x6, #32",   // 82
            "ldnp q0, q1, [x1]", // 83: load
            "add x1, x1, #32",   // 84
            "subs x2, x2, #32",  // 85
            "b.hi 12b",          // 86
            "13:",
            "add x1, x1, x2",         // 87
            "ldnp q2, q3, [x1]",      // 88: load, last 32 bytes, may overlap
            "stnp q0, q1, [x6]",      // 89
            "add x6, x6, x2",         // 90
            "stnp q2, q3, [x6, #32]", // 91
            "mov x0, #0",             // 92
            "ret",                    // 93
            "9:",
            "mov x0, #0", // 94: signal = 0 (success)
            "ret",        // 95
        )
    }

    // Instruction-for-instruction the glibc / Arm optimized-routines memcpy-advsimd, plus crash points.
    #[cfg(not(target_os = "macos"))]
    const SLICE_LOADS: [usize; 20] = [
        8, 9, 15, 16, 22, 23, 30, 31, 32, 38, 39, 46, 49, 56, 61, 63, 67, 69, 74, 76,
    ];
    #[cfg(not(target_os = "macos"))]
    const SLICE_RET: usize = 81;

    #[cfg(not(target_os = "macos"))]
    #[unsafe(naked)]
    pub extern "C" fn slice(
        _dst: *const u8, // x0
        _src: u64,       // x1
        _n: u64,         // x2
    ) -> VecResult {
        core::arch::naked_asm!(
            "add x4, x1, x2",      // 0: srcend
            "add x5, x0, x2",      // 1: dstend
            "cmp x2, #128",        // 2
            "b.hi 6f",             // 3
            "cmp x2, #32",         // 4
            "b.hi 4f",             // 5
            "cmp x2, #16",         // 6
            "b.lo 1f",             // 7
            "ldr q0, [x1]",        // 8: load, 16..=32
            "ldur q1, [x4, #-16]", // 9: load
            "str q0, [x0]",        // 10
            "stur q1, [x5, #-16]", // 11
            "mov x0, #0",          // 12
            "ret",                 // 13
            "1:",
            "tbz w2, #3, 2f",     // 14
            "ldr x6, [x1]",       // 15: load, 8..=15
            "ldur x7, [x4, #-8]", // 16: load
            "str x6, [x0]",       // 17
            "stur x7, [x5, #-8]", // 18
            "mov x0, #0",         // 19
            "ret",                // 20
            "2:",
            "tbz w2, #2, 3f",     // 21
            "ldr w6, [x1]",       // 22: load, 4..=7
            "ldur w8, [x4, #-4]", // 23: load
            "str w6, [x0]",       // 24
            "stur w8, [x5, #-4]", // 25
            "mov x0, #0",         // 26
            "ret",                // 27
            "3:",
            "cbz x2, 9f",           // 28
            "lsr x14, x2, #1",      // 29
            "ldrb w6, [x1]",        // 30: load, 1..=3
            "ldurb w10, [x4, #-1]", // 31: load
            "ldrb w8, [x1, x14]",   // 32: load
            "strb w6, [x0]",        // 33
            "strb w8, [x0, x14]",   // 34
            "sturb w10, [x5, #-1]", // 35
            "mov x0, #0",           // 36
            "ret",                  // 37
            "4:",
            "ldp q0, q1, [x1]",       // 38: load, 33..=128
            "ldp q2, q3, [x4, #-32]", // 39: load
            "cmp x2, #64",            // 40
            "b.hi 5f",                // 41
            "stp q0, q1, [x0]",       // 42
            "stp q2, q3, [x5, #-32]", // 43
            "mov x0, #0",             // 44
            "ret",                    // 45
            "5:",
            "ldp q4, q5, [x1, #32]",  // 46: load, 65..=128
            "cmp x2, #96",            // 47
            "b.ls 8f",                // 48
            "ldp q6, q7, [x4, #-64]", // 49: load, 97..=128
            "stp q6, q7, [x5, #-64]", // 50
            "8:",
            "stp q0, q1, [x0]",       // 51
            "stp q4, q5, [x0, #32]",  // 52
            "stp q2, q3, [x5, #-32]", // 53
            "mov x0, #0",             // 54
            "ret",                    // 55
            "6:",
            "ldr q3, [x1]", // 56: load, > 128: copy 16 bytes, then align src down to 16
            "and x14, x1, #15", // 57
            "and x1, x1, #-16", // 58
            "sub x3, x0, x14", // 59
            "add x2, x2, x14", // 60: n is now 16 too large
            "ldp q0, q1, [x1, #16]", // 61: load
            "str q3, [x0]", // 62
            "ldp q2, q3, [x1, #48]", // 63: load
            "subs x2, x2, #144", // 64
            "b.ls 7f",      // 65
            "10:",
            "stp q0, q1, [x3, #16]",  // 66: 64-byte blocks
            "ldp q0, q1, [x1, #80]",  // 67: load
            "stp q2, q3, [x3, #48]",  // 68
            "ldp q2, q3, [x1, #112]", // 69: load
            "add x1, x1, #64",        // 70
            "add x3, x3, #64",        // 71
            "subs x2, x2, #64",       // 72
            "b.hi 10b",               // 73
            "7:",
            "ldp q4, q5, [x4, #-64]", // 74: load, last 64 bytes, may overlap
            "stp q0, q1, [x3, #16]",  // 75
            "ldp q0, q1, [x4, #-32]", // 76: load
            "stp q2, q3, [x3, #48]",  // 77
            "stp q4, q5, [x5, #-64]", // 78
            "stp q0, q1, [x5, #-32]", // 79
            "9:",
            "mov x0, #0", // 80: signal = 0 (success)
            "ret",        // 81
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
