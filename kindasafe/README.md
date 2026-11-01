# kindasafe

Signal-safe memory reading for x86_64 and aarch64 on Linux.

Uses naked assembly functions to read memory, with crash recovery via SIGSEGV/SIGBUS signal handlers. When a read faults, the signal handler adjusts the program counter to skip past the faulting instruction and reports the error instead of crashing.

This is a `no_std` crate providing the core read primitives. Use [`kindasafe_init`](https://crates.io/crates/kindasafe_init) to install the required signal handlers.

## Usage

```rust
// First, initialize the signal handlers (requires kindasafe_init)
// SAFETY: Nothing else changes how SIGSEGV and SIGBUS are handled during
// initialization. Until now they were left at the default or handled by
// SA_SIGINFO functions that remain valid.
unsafe { kindasafe_init::init() }.expect("failed to init");

// Read a u64 from a potentially-invalid address
// SAFETY: init() succeeded above, and the result is validated before use
// because the target may be modified concurrently.
let value = unsafe { kindasafe::u64(some_address) };
match value {
    Ok(v) => println!("read: {v:#x}"),
    Err(e) => println!("fault: signal {}", e.signal),
}
```

## Supported architectures

- x86_64
- aarch64

## License

Apache-2.0
