# kindasafe_init

Signal handler initialization for the [kindasafe](https://crates.io/crates/kindasafe) signal-safe memory reading library.

Installs SIGSEGV and SIGBUS signal handlers that enable `kindasafe` to recover from memory access faults instead of crashing. Preserves any previously installed signal handlers as fallbacks.

## Usage

```rust
kindasafe_init::init().expect("failed to initialize kindasafe");

// SAFETY: the caller must satisfy the address, aliasing, initialization and
// concurrent-access requirements documented by `kindasafe::u64`.
let result = unsafe { kindasafe::u64(some_address) };
```

Initialization only makes a fault at an otherwise-invalid address recoverable.
It does not make an arbitrary address valid.

## License

Apache-2.0
