# kindasafe

Signal-safe memory reading for x86_64 and aarch64 on Linux.

Uses naked assembly functions to read memory, with crash recovery via SIGSEGV/SIGBUS signal handlers. When a read faults, the signal handler adjusts the program counter to skip past the faulting instruction and reports the error instead of crashing.

This is a `no_std` crate providing the core read primitives. Use [`kindasafe_init`](https://crates.io/crates/kindasafe_init) to install the required signal handlers.

AddressSanitizer builds explicitly check the source range after successful `u8`,
`u32`, `u64`, and `slice` reads, since naked assembly bypasses compiler instrumentation. Poisoned
reads produce an ASAN report; `ASAN_OPTIONS=halt_on_error=0` allows continuing after
the report. Faulting reads also produce an ASAN report after recovery, then
return `ReadMemError` when reporting is configured to continue. Normal builds
contain no ASAN checks or runtime dependency.

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

When reading from a SIGPROF sampling handler, check that SIGSEGV and SIGBUS
are unblocked on that thread. The recovery handlers block SIGPROF while they
run, but other code may still block recovery signals before sampling starts.

## Supported architectures

- x86_64
- aarch64

## License

Apache-2.0
