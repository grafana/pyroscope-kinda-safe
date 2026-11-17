#![cfg(kindasafe_asan)]

use std::hint::black_box;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn __asan_poison_memory_region(addr: *const u8, len: usize);
    fn __asan_unpoison_memory_region(addr: *const u8, len: usize);
}

const PROBE: &str = "KINDASAFE_ASAN_PROBE";
static SIGNAL_ADDRESS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn sample(_: libc::c_int) {
    let at = SIGNAL_ADDRESS.load(Ordering::Relaxed) as u64;
    // Deliberately invalid access: this subprocess must fail under ASan.
    black_box(unsafe { kindasafe::u64(at) }.unwrap());
}

#[test]
fn probe() {
    let Ok(case) = std::env::var(PROBE) else {
        return;
    };
    // ASan initialization must leave its runtime's signal handlers in place.
    unsafe { kindasafe_init::init() }.unwrap();
    assert!(kindasafe::sanity_check());
    assert_eq!(kindasafe_init::sanity_check(), Ok(()));
    assert!(kindasafe::crash_points().crash_points.is_empty());
    assert_eq!(kindasafe::recovered_faults(), 0);

    let data = Box::new([7u64; 3]);
    let at = black_box(data.as_ptr() as usize);
    let bad = (at + 8) as *const u8;
    // The allocation is live and aligned. Poison the middle word to exercise
    // unaligned loads and copies whose first and last bytes are unpoisoned.
    unsafe { __asan_poison_memory_region(bad, 8) };

    let fault = if case.starts_with("faulting_") || case == "unmapped_word" {
        unsafe {
            let size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let map = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            );
            assert_ne!(map, libc::MAP_FAILED);
            if case == "unmapped_word" {
                assert_eq!(libc::munmap(map, size), 0);
            }
            black_box(map as u64)
        }
    } else {
        0
    };

    // Invalid cases intentionally violate the read contract to test diagnostics.
    // Valid cases use initialized bytes with no concurrent writes or aliases.
    unsafe {
        match case.as_str() {
            "word" => {
                black_box(kindasafe::u64((at + 8) as u64).unwrap());
            }
            "unaligned_word" => {
                black_box(kindasafe::u64((at + 4) as u64).unwrap());
            }
            "u8" => {
                black_box(kindasafe::u8((at + 8) as u64).unwrap());
            }
            "u32" => {
                black_box(kindasafe::u32((at + 8) as u64).unwrap());
            }
            "unaligned_u32" => {
                black_box(kindasafe::u32((at + 6) as u64).unwrap());
            }
            "slice" => {
                let mut out = [0; 24];
                kindasafe::slice(&mut out, at as u64).unwrap();
                black_box(out);
            }
            "signal_word" | "faulting_signal_word" => {
                let address = if case == "signal_word" {
                    at + 8
                } else {
                    fault as usize
                };
                SIGNAL_ADDRESS.store(address, Ordering::Relaxed);
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
                assert_eq!(kindasafe::u8((at + 7) as u64).unwrap(), 0);
                assert_eq!(kindasafe::u32(at as u64).unwrap(), 7);
                assert_eq!(kindasafe::u32((at + 4) as u64).unwrap(), 0);
                assert_eq!(kindasafe::u32((at + 1) as u64).unwrap(), 0);
                let mut out = [0; 8];
                kindasafe::slice(&mut out, at as u64).unwrap();
                assert_eq!(out, 7u64.to_ne_bytes());
                kindasafe::slice(&mut [], (at + 8) as u64).unwrap();
                kindasafe::slice(&mut [], 0).unwrap();
            }
            "faulting_u8" => {
                black_box(kindasafe::u8(fault).unwrap());
            }
            "faulting_u32" => {
                black_box(kindasafe::u32(fault).unwrap());
            }
            "faulting_word" | "unmapped_word" => {
                black_box(kindasafe::u64(fault).unwrap());
            }
            "faulting_slice" => {
                let mut out = [0; 8];
                kindasafe::slice(&mut out, fault).unwrap();
                black_box(out);
            }
            _ => panic!("unknown probe {case}"),
        }
        __asan_unpoison_memory_region(bad, 8);
    }
    assert_eq!(kindasafe::recovered_faults(), 0);
    println!("probe completed");
}

fn run_probe(case: &str, expect_success: bool) -> String {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "probe", "--nocapture"])
        .env(PROBE, case)
        .env(
            "ASAN_OPTIONS",
            "detect_leaks=0:halt_on_error=1:handle_segv=1:handle_sigbus=1",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Drain both streams while waiting: a full diagnostic pipe must not look
    // like a signal-handler deadlock.
    fn drain(mut stream: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            String::from_utf8_lossy(&bytes).into_owned()
        })
    }
    let stdout = drain(child.stdout.take().unwrap());
    let stderr = drain(child.stderr.take().unwrap());
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            child.kill().unwrap();
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    assert!(!timed_out, "{case}: timed out\n{stdout}\n{stderr}");
    assert_eq!(
        status.success(),
        expect_success,
        "{case}: {stdout}\n{stderr}"
    );
    assert_eq!(
        stdout.contains("probe completed"),
        expect_success,
        "{case}: {stdout}\n{stderr}"
    );
    stderr
}

#[test]
fn reports_poisoned_reads() {
    for case in [
        "word",
        "unaligned_word",
        "u8",
        "u32",
        "unaligned_u32",
        "slice",
        "signal_word",
    ] {
        let stderr = run_probe(case, false);
        assert_eq!(
            stderr.matches("ERROR: AddressSanitizer").count(),
            1,
            "{case}: {stderr}"
        );
        assert!(stderr.contains("use-after-poison"), "{case}: {stderr}");
        assert!(stderr.contains("READ of size"), "{case}: {stderr}");
    }
}

#[test]
fn valid_and_empty_reads_do_not_report() {
    let stderr = run_probe("valid", true);
    assert!(!stderr.contains("AddressSanitizer"), "{stderr}");
}

#[test]
fn faults_reach_asan_without_recovery() {
    for case in [
        "faulting_u8",
        "faulting_u32",
        "faulting_word",
        "faulting_slice",
        "faulting_signal_word",
        "unmapped_word",
    ] {
        let stderr = run_probe(case, false);
        assert!(
            stderr.contains("AddressSanitizer: SEGV") || stderr.contains("AddressSanitizer: BUS"),
            "{case}: {stderr}"
        );
        assert!(stderr.contains("READ memory access"), "{case}: {stderr}");
    }
}
