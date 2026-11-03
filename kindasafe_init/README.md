# kindasafe_init

Signal handler initialization for the [kindasafe](https://crates.io/crates/kindasafe) signal-safe memory reading library.

Installs SIGSEGV and SIGBUS signal handlers that enable `kindasafe` to recover from memory access faults instead of crashing. Preserves any previously installed signal handlers as fallbacks.

## Usage

```rust
// SAFETY: No other code changes these signal handlers during initialization.
// Previous handlers remain valid for as long as kindasafe may call them.
unsafe { kindasafe_init::init() }.expect("failed to initialize kindasafe");

// SAFETY: The recovery handlers are still installed, and SIGSEGV and SIGBUS
// are unblocked on this thread. The result will be treated as untrusted bytes.
let result = unsafe { kindasafe::u64(some_address) };
```

Initialization is serialized and its result is cached, including failures. The
previous handlers are published atomically before the new handlers become
active, so signals can safely chain to them during installation. Signals that
`kindasafe` does not recover from go to the previous handler: `SIG_IGN`
and `SIG_DFL` keep their meaning, and handlers are called with the signature
selected by their `SA_SIGINFO` flag. The installed handlers inherit the other
flags of the previous handlers, such as `SA_ONSTACK`. Initialization fails with
`InitError::UnsupportedPreviousHandler` and leaves the previous handlers in
place if one of them was installed with `SA_RESETHAND`, because the kernel
would remove the `kindasafe` handler after the first fault. macOS does not
report `SA_RESETHAND`, so there such a handler is accepted and called on every
signal that `kindasafe` does not recover from, not only the first.
Initialization also fails on macOS if one of the previous handlers is
`SIG_IGN`: the kernel does not report whether a SIGSEGV or SIGBUS was sent by
another process, which `SIG_IGN` drops, or caused by a fault, which must still
terminate the process.
The installed handlers also keep each previous handler's signal mask and add
`SIGPROF`, so sampling cannot interrupt recovery or a directly chained previous
handler. This does not ensure SIGSEGV and SIGBUS are unblocked when sampling
starts; a sampler must check the current thread before a protected read.

Coordinate initialization with any other code that installs SIGSEGV or SIGBUS
handlers: querying the previous handler and replacing it require separate
system calls.

## License

Apache-2.0
