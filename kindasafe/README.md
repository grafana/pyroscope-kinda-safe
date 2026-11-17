# kindasafe

Signal-safe memory reading for x86_64 and aarch64 on Linux.

Uses naked assembly functions to read memory, with crash recovery via SIGSEGV/SIGBUS signal handlers. When a read faults, the signal handler adjusts the program counter to skip past the faulting instruction and reports the error instead of crashing.

This is a `no_std` crate providing the core read primitives. Use [`kindasafe_init`](https://crates.io/crates/kindasafe_init) to install the required signal handlers.

Normal builds recover faults to keep the target application running when the
unwinder encounters a bug. `kindasafe::recovered_faults() -> u64` exposes a
cumulative, process-local count of public reads returning `ReadMemError`. Each
failed slice counts once, including partially completed copies. Successful
reads, deliberate sanity checks, and signals forwarded to previous handlers do
not increment it. The lock-free counter uses relaxed atomics, wraps on overflow,
and has no reset API. Export its value through the embedding profiler's metrics
system; no exporter runs in the read path.

AddressSanitizer builds use ordinary compiler-instrumented Rust loads and
forward byte copies instead of assembly. They install no recovery handlers,
perform no manual poison checks, and make no manual ASan reporting calls.
Successful reads return `Ok`; invalid accesses are left to ASan or fatal-signal
handling. Both sanity checks skip their deliberate invalid read, and
`recovered_faults()` always returns zero. Empty slices never access the source.

ASan source memory must contain initialized bytes and satisfy Rust's pointer and
aliasing rules. No other thread may write or free those bytes during inspection.
These requirements are stronger than the normal assembly backend's concurrent
read contract. ASan does not make undefined behavior valid or guarantee that
every invalid access is detected.

ASan builds are for diagnosing unwinder bugs. An invalid read is a test failure,
so we accept ASan's standard fatal reporting even inside SIGPROF. That reporting
is not guaranteed async-signal-safe: it can deadlock if the interrupted thread
holds a lock the reporter needs. Diagnostics are therefore best-effort, and
fault tests use subprocess timeouts. This tradeoff is limited to ASan builds;
normal builds recover faults without invoking ASan.

## Usage

```rust
// First, initialize the signal handlers (requires kindasafe_init)
// SAFETY: Nothing else changes how SIGSEGV and SIGBUS are handled during
// initialization. Until now they were left at the default or handled by
// SA_SIGINFO functions that remain valid.
unsafe { kindasafe_init::init() }.expect("failed to init");

// Read a u64 from a potentially-invalid address
// SAFETY: init() succeeded, its handlers remain installed, and SIGSEGV and
// SIGBUS are unblocked on this thread. The result is validated before use
// because the target may be modified concurrently.
let value = unsafe { kindasafe::u64(some_address) };
match value {
    Ok(v) => println!("read: {v:#x}"),
    Err(e) => println!("fault: signal {}", e.signal),
}
```

`kindasafe::u32(address)` reads exactly four bytes in one load and returns a
`Result<u32, ReadMemError>`, with the same safety requirements as `u64`. This
avoids a byte-wise copy when reading 32-bit fields such as Python instruction
offsets. `kindasafe::u8(address)` reads exactly one byte and returns a
`Result<u8, ReadMemError>`, suitable for fields such as Python frame owners.

In normal builds, when reading from a SIGPROF sampling handler, check that SIGSEGV and SIGBUS
are unblocked on that thread. The recovery handlers block SIGPROF while they
run, but other code may still block recovery signals before sampling starts.

## Supported architectures

- x86_64
- aarch64

## License

Apache-2.0
