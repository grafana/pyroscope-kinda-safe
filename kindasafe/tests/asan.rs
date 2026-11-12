#![cfg(kindasafe_asan)]

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

unsafe extern "C" {
    fn __asan_poison_memory_region(addr: *const u8, len: usize);
    fn __asan_unpoison_memory_region(addr: *const u8, len: usize);
    fn __asan_region_is_poisoned(addr: *const u8, len: usize) -> *const u8;
}

const PROBE: &str = "KINDASAFE_ASAN_PROBE";
static SIGNAL_ADDRESS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn sample(_: libc::c_int) {
    let at = SIGNAL_ADDRESS.load(Ordering::Relaxed) as u64;
    // SAFETY: the probe initializes recovery and keeps its handlers installed.
    // The source is a separate allocation without live exclusive borrows.
    unsafe { kindasafe::u64(at) }.unwrap();
}

#[test]
fn probe() {
    let Ok(case) = std::env::var(PROBE) else {
        return;
    };
    // SAFETY: no other code changes recovery handlers in this subprocess.
    unsafe { kindasafe_init::init() }.unwrap();

    // The middle word is poisoned, so the slice check must inspect more than
    // its first/last byte and the unaligned word check must include its tail.
    let data = Box::new([7u64; 3]);
    let at = data.as_ptr() as usize;
    let bad = (at + 8) as *const u8;
    // SAFETY: the allocation is live, aligned, and exclusively owned by this test.
    unsafe {
        __asan_poison_memory_region(bad, 8);
        assert_eq!(__asan_region_is_poisoned(at as *const u8, 24), bad);
    }
    println!("bad {:#x}", bad as usize);

    // SAFETY: recovery is initialized. The allocation remains live without any
    // exclusive borrows of the source; poisoning is deliberate test input.
    unsafe {
        match case.as_str() {
            "word" => {
                kindasafe::u64((at + 8) as u64).unwrap();
            }
            "unaligned_word" => {
                kindasafe::u64((at + 4) as u64).unwrap();
            }
            "u8" => {
                kindasafe::u8((at + 8) as u64).unwrap();
            }
            "u32" => {
                kindasafe::u32((at + 8) as u64).unwrap();
            }
            "unaligned_u32" => {
                kindasafe::u32((at + 6) as u64).unwrap();
            }
            "slice" => {
                kindasafe::slice(&mut [0; 24], at as u64).unwrap();
            }
            "signal_word" => {
                SIGNAL_ADDRESS.store(at + 8, Ordering::Relaxed);
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = sample as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGPROF, &action, std::ptr::null_mut()),
                    0
                );
                assert_eq!(libc::raise(libc::SIGPROF), 0);
            }
            "valid" => {
                assert_eq!(kindasafe::u64(at as u64).unwrap(), 7);
                assert_eq!(kindasafe::u8(at as u64).unwrap(), 7);
                // A one-byte read must not include the following poisoned byte.
                assert_eq!(kindasafe::u8((at + 7) as u64).unwrap(), 0);
                assert_eq!(kindasafe::u32(at as u64).unwrap(), 7);
                // Poison starts immediately after these four readable bytes.
                assert_eq!(kindasafe::u32((at + 4) as u64).unwrap(), 0);
                let mut out = [0; 8];
                kindasafe::slice(&mut out, at as u64).unwrap();
                assert_eq!(out, 7u64.to_ne_bytes());
                kindasafe::slice(&mut [], (at + 8) as u64).unwrap();
                kindasafe::slice(&mut [], 0).unwrap();
            }
            "faulting_u8" => {
                assert!(kindasafe::u8(0).is_err());
            }
            "faulting_u32" => {
                assert!(kindasafe::u32(0).is_err());
            }
            "faulting_word" => {
                assert!(kindasafe::u64(0).is_err());
            }
            "faulting_slice" => {
                let mut out = [0; 8];
                assert!(kindasafe::slice(&mut out, 0).is_err());
            }
            _ => panic!("unknown probe {case}"),
        }
        __asan_unpoison_memory_region(bad, 8);
    }
    println!("probe completed");
}

fn run_probe(case: &str) -> (String, String) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "probe", "--nocapture"])
        .env(PROBE, case)
        .env(
            "ASAN_OPTIONS",
            "detect_leaks=0:halt_on_error=0:handle_segv=0:handle_sigbus=0",
        )
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{case}: {stdout}\n{stderr}");
    assert!(
        stdout.contains("probe completed"),
        "{case}: {stdout}\n{stderr}"
    );
    (stdout, stderr)
}

#[test]
fn reports_poisoned_reads() {
    for (case, size) in [
        ("word", 8),
        ("unaligned_word", 4),
        ("u8", 1),
        ("u32", 4),
        ("unaligned_u32", 2),
        ("slice", 16),
        ("signal_word", 8),
    ] {
        let (stdout, stderr) = run_probe(case);
        let addr = stdout
            .lines()
            .find_map(|line| line.strip_prefix("bad "))
            .unwrap();
        assert_eq!(
            stderr.matches("ERROR: AddressSanitizer").count(),
            1,
            "{case}: {stderr}"
        );
        assert!(
            stderr.contains(&format!(
                "ERROR: AddressSanitizer: use-after-poison on address {addr} "
            )),
            "{case}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("READ of size {size} at {addr} ")),
            "{case}: {stderr}"
        );
    }
}

#[test]
fn valid_and_empty_reads_do_not_report() {
    let (_, stderr) = run_probe("valid");
    assert!(!stderr.contains("AddressSanitizer"), "{stderr}");
}

#[test]
fn reports_faulting_reads_after_recovery() {
    for (case, size) in [
        ("faulting_u8", 1),
        ("faulting_u32", 4),
        ("faulting_word", 8),
        ("faulting_slice", 8),
    ] {
        let (_, stderr) = run_probe(case);
        assert_eq!(
            stderr.matches("ERROR: AddressSanitizer").count(),
            1,
            "{case}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("READ of size {size} at 0x000000000000 ")),
            "{case}: {stderr}"
        );
        assert!(
            stderr.contains("AddressSanitizer: unknown-crash"),
            "{case}: {stderr}"
        );
    }
}
