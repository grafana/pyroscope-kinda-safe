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
        let f = libc::tmpfile();
        let m = libc::mmap(
            std::ptr::null_mut::<libc::c_void>(),
            4,
            libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            libc::fileno(f),
            0,
        );
        let m = m as *mut i32;
        cb(m as u64);

        libc::munmap(m as *mut libc::c_void, 4);
        libc::fclose(f);
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
