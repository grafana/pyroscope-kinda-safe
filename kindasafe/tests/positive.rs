use kindasafe::{Ptr, slice, u8, u32, u64};
use std::fmt;

// SAFETY: These tests only change signal handling through init(). Before that,
// signals use the default action or the test runtime's static handlers.
type TestResult<T = ()> = std::result::Result<T, TestError>;

enum TestError {
    Init(kindasafe_init::InitError),
    ReadMem(kindasafe::ReadMemError),
}

impl fmt::Debug for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init(err) => f.debug_tuple("Init").field(err).finish(),
            Self::ReadMem(err) => f.debug_tuple("ReadMem").field(err).finish(),
        }
    }
}

impl From<kindasafe_init::InitError> for TestError {
    fn from(err: kindasafe_init::InitError) -> Self {
        Self::Init(err)
    }
}

impl From<kindasafe::ReadMemError> for TestError {
    fn from(err: kindasafe::ReadMemError) -> Self {
        Self::ReadMem(err)
    }
}

// On macOS, accessing a PROT_NONE mmap page delivers SIGBUS;
// on Linux it delivers SIGSEGV.
#[cfg(target_os = "linux")]
const PROT_NONE_SIGNAL: u64 = libc::SIGSEGV as u64;
#[cfg(target_os = "macos")]
const PROT_NONE_SIGNAL: u64 = libc::SIGBUS as u64;

#[test]
fn test_init() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    unsafe { kindasafe_init::init() }?;
    Ok(())
}

#[test]
fn u64_aligned() -> TestResult {
    unsafe { kindasafe_init::init() }?;

    let x: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef];
    let x_ptr = x.as_ptr() as Ptr;

    let i = unsafe { u64(x_ptr) }?;
    assert_eq!(i, 0xefbeaddebebafeca);
    Ok(())
}

#[test]
fn u64_unaligned() -> TestResult {
    unsafe { kindasafe_init::init() }?;

    let x: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00];
    let x_ptr = x.as_ptr() as Ptr + 1;
    let i = unsafe { u64(x_ptr) }?;
    assert_eq!(i, 0xefbeaddebebafe);
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn u64_sigsegv() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    trigger_sigsegv(|p| {
        assert_eq!(
            unsafe { u64(p) },
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn u64_sigbus() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    trigger_sigbus(|p| {
        assert_eq!(
            unsafe { u64(p) },
            Err(kindasafe::ReadMemError {
                signal: libc::SIGBUS as u64
            })
        );
    });
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn u64_unaligned_page_boundary() -> TestResult {
    unsafe { kindasafe_init::init() }?;

    trigger_sigsegv_page_boundary(|p, ps| {
        let boundary = ps as u64;
        assert_eq!(unsafe { u64(p) }, Ok(0x6161616161616161));
        assert_eq!(unsafe { u64(p + boundary - 0x8) }, Ok(0x6161616161616161));
        assert_eq!(
            unsafe { u64(p + boundary - 0x7) },
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
        assert_eq!(
            unsafe { u64(p + boundary) },
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
fn u32_aligned() -> TestResult {
    unsafe { kindasafe_init::init() }?;

    for value in [0u32, 1, 0x8000_0000, 0xbeba_feca, u32::MAX] {
        let at = &value as *const u32 as Ptr;
        assert_eq!(unsafe { u32(at) }?, value);
    }
    Ok(())
}

#[test]
fn u32_unaligned() -> TestResult {
    unsafe { kindasafe_init::init() }?;

    let x: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0xde];
    let x_ptr = x.as_ptr() as Ptr + 1;
    let i = unsafe { u32(x_ptr) }?;
    assert_eq!(i, 0xdebebafe);
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn u32_sigsegv() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    trigger_sigsegv(|p| {
        assert_eq!(
            unsafe { u32(p) },
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn u32_sigbus() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    trigger_sigbus(|p| {
        assert_eq!(
            unsafe { u32(p) },
            Err(kindasafe::ReadMemError {
                signal: libc::SIGBUS as u64
            })
        );
    });
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn u8_sigsegv() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    trigger_sigsegv(|p| {
        assert_eq!(
            unsafe { u8(p) },
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn u8_sigbus() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    trigger_sigbus(|p| {
        assert_eq!(
            unsafe { u8(p) },
            Err(kindasafe::ReadMemError {
                signal: libc::SIGBUS as u64
            })
        );
    });
    Ok(())
}

#[test]
fn u8_values() -> TestResult {
    unsafe { kindasafe_init::init() }?;

    let values = [0u8, 1, 0x7f, 0x80, 0xff];
    for (offset, expected) in values.iter().enumerate() {
        assert_eq!(
            unsafe { u8(values.as_ptr() as Ptr + offset as Ptr) }?,
            *expected
        );
    }
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn u8_page_boundary() -> TestResult {
    unsafe { kindasafe_init::init() }?;

    trigger_sigsegv_page_boundary(|p, ps| {
        let boundary = p + ps as Ptr;
        // The last readable byte must succeed without touching the guard page.
        assert_eq!(unsafe { u8(boundary - 1) }, Ok(0x61));
        assert_eq!(
            unsafe { u8(boundary) },
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
        assert_eq!(unsafe { u8(boundary - 1) }, Ok(0x61));
    });
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn u32_unaligned_page_boundary() -> TestResult {
    unsafe { kindasafe_init::init() }?;

    trigger_sigsegv_page_boundary(|p, ps| {
        let boundary = ps as u64;
        assert_eq!(unsafe { u32(p) }, Ok(0x61616161));
        assert_eq!(unsafe { u32(p + boundary - 0x4) }, Ok(0x61616161));
        for readable in 1..4 {
            assert_eq!(
                unsafe { u32(p + boundary - readable) },
                Err(kindasafe::ReadMemError {
                    signal: PROT_NONE_SIGNAL
                })
            );
            assert_eq!(unsafe { u32(p + boundary - 4) }, Ok(0x61616161));
        }
        assert_eq!(
            unsafe { u32(p + boundary) },
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
fn vec_aligned() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    let mut buf = vec![0u8; 8];
    let x: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef];
    unsafe { slice(&mut buf, x.as_ptr() as Ptr) }?;
    assert_eq!(buf, x.clone());
    Ok(())
}

#[test]
fn vec_unaligned() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    let mut buf = vec![0u8; 8];
    let x: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xcc];
    let x_ptr = x.as_ptr() as Ptr + 1;
    unsafe { slice(&mut buf[0..7], x_ptr) }?;
    let expected: Vec<u8> = vec![0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0];
    assert_eq!(buf, expected);
    Ok(())
}

#[test]
fn slice_preserves_destination_bounds() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    let source = *b"hello\0";
    let at = source.as_ptr() as Ptr;
    let mut buf = [0xff; 8];

    unsafe { slice(&mut buf[1..7], at) }?;
    assert_eq!(&buf, b"\xffhello\0\xff");

    unsafe { slice(&mut buf[1..1], at) }?;
    assert_eq!(&buf, b"\xffhello\0\xff");
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn vec_sigsegv() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    trigger_sigsegv(|p| {
        let mut buf = [0u8; 8];
        assert_eq!(
            unsafe { slice(&mut buf, p as Ptr) },
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn vec_sigbus() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    trigger_sigbus(|p| {
        let mut buf = [0u8; 8];
        let res = unsafe { slice(&mut buf, p as Ptr) };
        assert_eq!(
            res,
            Err(kindasafe::ReadMemError {
                signal: libc::SIGBUS as u64
            })
        );
    });
    Ok(())
}
#[test]
#[cfg_attr(kindasafe_asan, ignore = "faulting reads are reported in ASAN tests")]
fn vec_sigsegv_page_boundary() -> TestResult {
    unsafe { kindasafe_init::init() }?;

    trigger_sigsegv_page_boundary(|p, ps| {
        let boundary = ps as u64;
        let mut buf = [0u8; 16];
        assert_eq!(
            unsafe { slice(&mut buf, (p + boundary - 8) as Ptr) },
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
        assert_eq!(
            buf,
            vec![
                0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0
            ]
            .as_slice()
        );
    });
    Ok(())
}

#[cfg(target_arch = "x86_64")]
const FAULT_INSTRUCTIONS: &[(kindasafe::Reg, &[u8])] = &[
    (kindasafe::Reg::Rdx, &[0x48, 0x8B, 0x07]), // mov rax, [rdi]
    (kindasafe::Reg::Rdx, &[0x8B, 0x07]),       // mov eax, [rdi]
    (kindasafe::Reg::Rdx, &[0x0F, 0xB6, 0x07]), // movzx eax, byte ptr [rdi]
    (kindasafe::Reg::Rax, &[0xF3, 0xA4]),       // rep movsb
];
#[cfg(target_arch = "x86_64")]
const RET: &[u8] = &[0xC3];

#[cfg(target_arch = "aarch64")]
const FAULT_INSTRUCTIONS: &[(kindasafe::Reg, &[u8])] = &[
    (kindasafe::Reg::X1, &0xF9400000u32.to_le_bytes()), // ldr x0, [x0]
    (kindasafe::Reg::X1, &0xB9400000u32.to_le_bytes()), // ldr w0, [x0]
    (kindasafe::Reg::X1, &0x39400000u32.to_le_bytes()), // ldrb w0, [x0]
    (kindasafe::Reg::X0, &0x38401423u32.to_le_bytes()), // ldrb w3, [x1], #1
];
#[cfg(target_arch = "aarch64")]
const RET: &[u8] = &0xD65F03C0u32.to_le_bytes();

// The crash point offsets are hand-maintained; a stale one makes the signal
// handler fall through to the fallback instead of recovering the read.
#[test]
fn crash_points_point_at_faulting_instruction_and_skip_to_ret() {
    let points = kindasafe::crash_points().crash_points;
    assert_eq!(points.len(), FAULT_INSTRUCTIONS.len());
    for (point, &(reg, fault)) in points.into_iter().zip(FAULT_INSTRUCTIONS) {
        assert_eq!(point.signal_reg, reg);
        let at_pc = unsafe { std::slice::from_raw_parts(point.pc as *const u8, fault.len()) };
        assert_eq!(
            at_pc, fault,
            "{:?}: pc is not the faulting instruction",
            point.signal_reg
        );
        let after_skip =
            unsafe { std::slice::from_raw_parts((point.pc + point.skip) as *const u8, RET.len()) };
        assert_eq!(
            after_skip, RET,
            "{:?}: pc + skip is not ret",
            point.signal_reg
        );
    }
}

// The destination is 2^32 + 1 bytes of address space backed by one 64 MiB
// file mapped repeatedly, so the copy commits 64 MiB rather than 4 GiB.
// Byte 2^32 aliases byte 0. The copy is observed through raw pointers because
// the aliasing breaks the uniqueness the slice type promises.
#[cfg(target_arch = "x86_64")]
#[test]
fn slice_copies_more_than_4gib() -> TestResult {
    unsafe { kindasafe_init::init() }?;
    const CHUNK: usize = 64 << 20;
    const N: usize = (1 << 32) + 1;
    const TOTAL: usize = N.div_ceil(CHUNK) * CHUNK;
    const MARKER: u8 = 0xAB;
    unsafe {
        let mut template = *b"/tmp/kindasafe_alias_XXXXXX\0";
        let fd = libc::mkstemp(template.as_mut_ptr() as *mut libc::c_char);
        assert!(fd >= 0, "mkstemp failed");
        libc::unlink(template.as_ptr() as *const libc::c_char);
        assert_eq!(
            libc::ftruncate(fd, CHUNK as libc::off_t),
            0,
            "ftruncate failed"
        );

        let dst = libc::mmap(
            std::ptr::null_mut(),
            TOTAL,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(dst, libc::MAP_FAILED, "reserving the destination failed");
        let dst = dst as *mut u8;
        for i in 0..TOTAL / CHUNK {
            let want = dst.add(i * CHUNK);
            let got = libc::mmap(
                want as *mut libc::c_void,
                CHUNK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                0,
            );
            assert_eq!(got as *mut u8, want, "aliasing chunk {i} failed");
        }

        let src = libc::mmap(
            std::ptr::null_mut(),
            N,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_NORESERVE,
            -1,
            0,
        );
        assert_ne!(src, libc::MAP_FAILED, "mapping the source failed");
        let src = src as *mut u8;
        src.add(N - 1).write_volatile(MARKER);

        let res = slice(std::slice::from_raw_parts_mut(dst, N), src as Ptr);
        let last = dst.add(N - 1).read_volatile();
        let first = dst.read_volatile();

        libc::munmap(dst as *mut libc::c_void, TOTAL);
        libc::munmap(src as *mut libc::c_void, N);
        libc::close(fd);

        res?;
        assert_eq!(last, MARKER, "byte 1 << 32 was not copied");
        assert_eq!(first, MARKER, "byte 0 should alias byte 1 << 32");
    }
    Ok(())
}

fn page_size() -> usize {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(ps > 0, "sysconf(_SC_PAGESIZE) failed");
    ps as usize
}

fn trigger_sigsegv_page_boundary<F>(mut cb: F)
where
    F: FnMut(Ptr, usize),
{
    let ps = page_size();
    let map_size = 2 * ps;
    unsafe {
        let x_ptr = libc::mmap(
            std::ptr::null_mut::<libc::c_void>(),
            map_size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(libc::MAP_FAILED, x_ptr, "mmap failed");
        let x_ptr = x_ptr as usize;
        let ret = libc::mprotect(
            x_ptr as *mut libc::c_void,
            ps,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        assert_eq!(ret, 0, "mprotect failed");
        libc::memset(x_ptr as *mut libc::c_void, 0x61, ps);

        cb(x_ptr as Ptr, ps);

        libc::munmap(x_ptr as *mut libc::c_void, map_size);
    }
}

pub fn trigger_sigbus<F>(mut cb: F)
where
    F: FnMut(u64),
{
    unsafe {
        // Not tmpfile(): on macOS it wraps mkstemp/unlink in a process-wide
        // sigprocmask(SIG_BLOCK, all)/restore pair; concurrent calls race and
        // can leave every signal permanently blocked, livelocking the fault
        // tests (github.com/grafana/pyroscope-kinda-safe/issues/36).
        let mut template = *b"/tmp/kindasafe_sigbus_XXXXXX\0";
        let f = libc::mkstemp(template.as_mut_ptr() as *mut libc::c_char);
        assert!(f >= 0, "mkstemp failed");
        libc::unlink(template.as_ptr() as *const libc::c_char);
        let m = libc::mmap(
            std::ptr::null_mut::<libc::c_void>(),
            4,
            libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            f,
            0,
        );
        let m = m as *mut i32;
        cb(m as u64);

        libc::munmap(m as *mut libc::c_void, 4);
        libc::close(f);
    };
}

pub fn trigger_sigsegv<F>(mut cb: F)
where
    F: FnMut(u64),
{
    unsafe {
        let m = libc::mmap(
            std::ptr::null_mut::<libc::c_void>(),
            4,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(libc::MAP_FAILED, m);
        let m = m as *mut i32;
        cb(m as u64);

        libc::munmap(m as *mut libc::c_void, 4);
    };
}
