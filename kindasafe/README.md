# kindasafe

Signal-safe memory reading for x86_64 and aarch64 on Linux.

Uses naked assembly functions to read memory, with crash recovery via SIGSEGV/SIGBUS signal handlers. When a read faults, the signal handler adjusts the program counter to skip past the faulting instruction and reports the error instead of crashing.

This is a `no_std` crate providing the core read primitives. Use [`kindasafe_init`](https://crates.io/crates/kindasafe_init) to install the required signal handlers.

## Safety

Functions that read or write at a caller-supplied raw address (`u64`, `slice`,
`str`, and the architecture entry points) are `unsafe`. Callers must uphold the
`# Safety` contract for the function they use, including address validity,
aliasing and concurrent-access rules, initialized data, and fault-recovery
preconditions. The recovery handlers are process-wide, but the relevant fault
signal must be deliverable on the reading thread. Fault recovery is a
speculative-read mechanism, not a substitute for a valid pointer.

## Usage

```rust
// First, initialize the signal handlers (requires kindasafe_init)
kindasafe_init::init().expect("failed to init");

// SAFETY: `some_address` must be valid for an 8-byte read, or a fault there
// must be recoverable by the process-wide handlers installed above, with the
// fault signal deliverable on this thread. The memory must not be concurrently
// mutated.
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
