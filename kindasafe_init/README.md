# kindasafe_init

Signal handler initialization for the [kindasafe](https://crates.io/crates/kindasafe) signal-safe memory reading library.

Installs SIGSEGV and SIGBUS signal handlers that enable `kindasafe` to recover from memory access faults instead of crashing. Preserves any previously installed signal handlers as fallbacks.

## Usage

```rust
// SAFETY: No other code changes these dispositions during initialization.
// Previous handlers remain valid for as long as kindasafe may call them.
unsafe { kindasafe_init::init() }.expect("failed to initialize kindasafe");

// Now kindasafe reads will recover from faults
let result = kindasafe::u64(some_address);
```

Initialization is serialized and its result is cached, including failures. The
previous dispositions are published atomically before the new handlers become
active, so signals can safely chain to them during installation. Signals that
`kindasafe` does not recover from honor the previous disposition: `SIG_IGN`
and `SIG_DFL` keep their meaning, and handlers are called with the signature
selected by their `SA_SIGINFO` flag.
Coordinate initialization with any other code that installs SIGSEGV or SIGBUS
handlers: querying the previous disposition and replacing it require separate
system calls.

## License

Apache-2.0
