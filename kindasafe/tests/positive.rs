use kindasafe::{Ptr, slice, u64};
use std::fmt;

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
    kindasafe_init::init()?;
    kindasafe_init::init()?;
    Ok(())
}

#[test]
fn u64_aligned() -> TestResult {
    kindasafe_init::init()?;

    let x: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef];
    let x_ptr = x.as_ptr() as Ptr;

    let i = u64(x_ptr)?;
    assert_eq!(i, 0xefbeaddebebafeca);
    Ok(())
}

#[test]
fn u64_unaligned() -> TestResult {
    kindasafe_init::init()?;

    let x: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00];
    let x_ptr = x.as_ptr() as Ptr + 1;
    let i = u64(x_ptr)?;
    assert_eq!(i, 0xefbeaddebebafe);
    Ok(())
}

#[test]
fn u64_sigsegv() -> TestResult {
    kindasafe_init::init()?;
    trigger_sigsegv(|p| {
        assert_eq!(
            u64(p),
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
fn u64_sigbus() -> TestResult {
    kindasafe_init::init()?;
    trigger_sigbus(|p| {
        assert_eq!(
            u64(p),
            Err(kindasafe::ReadMemError {
                signal: libc::SIGBUS as u64
            })
        );
    });
    Ok(())
}

#[test]
fn u64_unaligned_page_boundary() -> TestResult {
    kindasafe_init::init()?;

    trigger_sigsegv_page_boundary(|p, ps| {
        let boundary = ps as u64;
        assert_eq!(u64(p), Ok(0x6161616161616161));
        assert_eq!(u64(p + boundary - 0x8), Ok(0x6161616161616161));
        assert_eq!(
            u64(p + boundary - 0x7),
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
        assert_eq!(
            u64(p + boundary),
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
fn vec_aligned() -> TestResult {
    kindasafe_init::init()?;
    let mut buf = vec![0u8; 8];
    let x: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef];
    slice(&mut buf, x.as_ptr() as Ptr)?;
    assert_eq!(buf, x.clone());
    Ok(())
}

#[test]
fn vec_unaligned() -> TestResult {
    kindasafe_init::init()?;
    let mut buf = vec![0u8; 8];
    let x: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xcc];
    let x_ptr = x.as_ptr() as Ptr + 1;
    slice(&mut buf[0..7], x_ptr)?;
    let expected: Vec<u8> = vec![0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0];
    assert_eq!(buf, expected);
    Ok(())
}

#[test]
fn vec_sigsegv() -> TestResult {
    kindasafe_init::init()?;
    trigger_sigsegv(|p| {
        let mut buf = [0u8; 8];
        assert_eq!(
            slice(&mut buf, p as Ptr),
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
fn vec_sigbus() -> TestResult {
    kindasafe_init::init()?;
    trigger_sigbus(|p| {
        let mut buf = [0u8; 8];
        let res = slice(&mut buf, p as Ptr);
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
fn vec_sigsegv_page_boundary() -> TestResult {
    kindasafe_init::init()?;

    trigger_sigsegv_page_boundary(|p, ps| {
        let boundary = ps as u64;
        let mut buf = [0u8; 16];
        assert_eq!(
            slice(&mut buf, (p + boundary - 8) as Ptr),
            Err(kindasafe::ReadMemError {
                signal: PROT_NONE_SIGNAL
            })
        );
    });
    Ok(())
}

#[test]
fn vec_sizes_and_alignments() -> TestResult {
    kindasafe_init::init()?;
    let src: Vec<u8> = (0..1200).map(|i| (i * 7 + 1) as u8).collect();
    for n in 0..=1100 {
        for off in 0..16 {
            let mut buf = vec![0u8; n + 32];
            slice(&mut buf[off..off + n], src.as_ptr() as Ptr + off as Ptr)?;
            assert_eq!(&buf[off..off + n], &src[off..off + n], "n={n} off={off}");
            assert!(buf[..off].iter().all(|&b| b == 0), "n={n} off={off}");
            assert!(buf[off + n..].iter().all(|&b| b == 0), "n={n} off={off}");
        }
    }
    Ok(())
}

#[test]
fn vec_sigsegv_page_boundary_all_sizes() -> TestResult {
    kindasafe_init::init()?;
    trigger_sigsegv_page_boundary(|p, ps| {
        let boundary = p + ps as u64;
        for n in 1..=ps.min(1100) {
            let mut buf = vec![0u8; n];
            assert_eq!(slice(&mut buf, boundary - n as u64), Ok(()), "n={n}");
            assert!(buf.iter().all(|&b| b == 0x61), "n={n}");
            for over in [
                1,
                2,
                3,
                4,
                7,
                8,
                15,
                16,
                31,
                32,
                33,
                63,
                64,
                65,
                96,
                97,
                127,
                128,
                129,
                n - 1,
                n,
            ] {
                if over == 0 || over > n {
                    continue;
                }
                let at = boundary - (n - over) as u64;
                assert_eq!(
                    slice(&mut buf, at),
                    Err(kindasafe::ReadMemError {
                        signal: PROT_NONE_SIGNAL
                    }),
                    "n={n} over={over}"
                );
            }
        }
    });
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

#[test]
fn vec_guard_before_start_all_sizes() -> TestResult {
    kindasafe_init::init()?;
    let ps = page_size();
    unsafe {
        let m = libc::mmap(
            std::ptr::null_mut::<libc::c_void>(),
            2 * ps,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(libc::MAP_FAILED, m, "mmap failed");
        let m = m as usize;
        assert_eq!(
            libc::mprotect(m as *mut libc::c_void, ps, libc::PROT_NONE),
            0
        );
        let data = m + ps;
        for i in 0..ps {
            *((data + i) as *mut u8) = (i * 13 + 5) as u8;
        }
        for n in 1..=ps.min(1100) {
            for off in 0..16 {
                let mut buf = vec![0u8; n];
                slice(&mut buf, (data + off) as Ptr)?;
                let src = std::slice::from_raw_parts((data + off) as *const u8, n);
                assert_eq!(buf, src, "n={n} off={off}");
            }
        }
        libc::munmap(m as *mut libc::c_void, 2 * ps);
    }
    Ok(())
}

#[test]
fn crash_points_are_loads() {
    for (i, point) in kindasafe::crash_points().crash_points.iter().enumerate() {
        let at = |off: usize| unsafe { *((point.pc + off) as *const u8) };
        #[cfg(target_arch = "x86_64")]
        {
            let rex = (0x40..=0x4f).contains(&at(0)) as usize;
            let load = matches!(
                (at(rex), at(rex + 1)),
                (0x0f, 0x10) | (0x0f, 0xb7) | (0x8a, _) | (0x8b, _)
            );
            assert!(load, "crash point {i} at {:#x} is not a load", point.pc);
            assert_eq!(at(point.skip), 0xc3, "crash point {i} does not skip to ret");
        }
        #[cfg(target_arch = "aarch64")]
        {
            let word =
                |off: usize| u32::from_le_bytes([at(off), at(off + 1), at(off + 2), at(off + 3)]);
            let insn = word(0);
            let load = (insn >> 27) & 1 == 1 && (insn >> 25) & 1 == 0 && (insn >> 22) & 1 == 1;
            assert!(
                load,
                "crash point {i} at {:#x} is not a load: {insn:#010x}",
                point.pc
            );
            assert_eq!(
                word(point.skip),
                0xd65f03c0,
                "crash point {i} does not skip to ret"
            );
        }
    }
}

#[test]
fn crash_point_lookup_matches_table() {
    for point in kindasafe::crash_points().crash_points.iter() {
        let found = kindasafe::crash_point(point.pc).expect("crash point not found by pc");
        assert_eq!(found.skip, point.skip);
        assert_eq!(found.signal_reg, point.signal_reg);
        assert!(kindasafe::crash_point(point.pc + 1).is_none());
    }
}
