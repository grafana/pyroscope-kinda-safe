# kindasafe

Signal-safe memory reading for x86_64 and aarch64 on Linux and macOS.

Uses naked assembly functions to read memory, with crash recovery via SIGSEGV/SIGBUS signal handlers. When a read faults, the signal handler adjusts the program counter to skip past the faulting instruction and reports the error instead of crashing.

This is a `no_std` crate providing the core read primitives. Use [`kindasafe_init`](https://crates.io/crates/kindasafe_init) to install the required signal handlers.

## Recovery preconditions

A read can recover from an inaccessible address only when **all** of the
following are true at the moment the fault occurs:

1. `kindasafe_init::init()` has completed successfully in this process.
2. SIGSEGV and SIGBUS still point at kindasafe's recovery handlers. A later
   `sigaction` call by another component can replace them.
3. The thread performing the read has **both** SIGSEGV and SIGBUS unblocked.
4. No interrupted signal handler has temporarily blocked SIGSEGV or SIGBUS on
   that thread. Signal masks are per-thread and are inherited by nested signal
   handlers.

If a required fault signal is blocked, the fault cannot be diverted to the
recovery handler. On Linux, a synchronous SIGSEGV/SIGBUS while that signal is
blocked normally terminates the process with the default action (observed as
exit status 139 for SIGSEGV); restoring the mask afterwards does not help
because the process never resumes. Do not wrap `kindasafe` reads in
`sigprocmask`/`pthread_sigmask` calls that block SIGSEGV or SIGBUS.

### Profiling signal handlers

A profiling signal can interrupt an application signal handler that has
temporarily blocked SIGSEGV or SIGBUS. The profiling callback inherits that
blocked mask, so an inaccessible-address `kindasafe` read in the callback
cannot be recovered even though the interrupted application code would
otherwise be able to recover. The same applies to callbacks that explicitly
block fault signals.

Check the current thread before each potentially-faulting read:

```rust
use kindasafe_init::{init, recovery_available};

init().expect("failed to initialize kindasafe recovery");

fn sample(address: kindasafe::Ptr) {
    // Do this first (or at the start of the sampling callback) and skip the
    // sample when recovery is not currently possible.
    if recovery_available().is_err() {
        return;
    }

    match kindasafe::u64(address) {
        Ok(value) => { /* use value */ }
        Err(error) => { /* inaccessible address, signal number in error.signal */ }
    }
}
```

`recovery_available()` checks the current thread's mask and verifies that the
SIGSEGV/SIGBUS handlers are still kindasafe's. It does not modify any signal
state. It is best-effort: another thread can replace a handler, or code can
change the mask, between the check and the read. Call it at the integration
boundary (for example once per profile sample), not before every primitive read
in a loop.

Do not clear SIGSEGV/SIGBUS from the application's mask from inside a profiling
handler. That silently changes application signal semantics and can deliver
unrelated faults in the middle of the handler. If a profiling library installs
its own handler with `sa_mask`, leave SIGSEGV and SIGBUS out of that mask.

## Initialization guidance

- Call `kindasafe_init::init()` once from normal code before any potentially
  faulting reads. It is idempotent and returns the first result, including an
  error; it does not retry or repair later handler replacement.
- Install kindasafe after any component that also owns SIGSEGV/SIGBUS handlers,
  or make sure later installers preserve kindasafe's recovery behavior.
  `init()` saves the previous handlers as fallbacks, but a handler installed
  *after* `init()` takes precedence over kindasafe.
- `init()` does not change the calling thread's signal mask. It cannot make a
  blocked signal recoverable.
- `kindasafe_init::recovery_available()` returns an actionable error
  (`NotInitialized`, `InitializationFailed`, `HandlerNotInstalled`, or
  `SignalBlocked`). Handle all of these as "skip this read".

The core crate cannot enforce these conditions automatically without adding a
platform signal-mask check to every read. That would add a syscall to a hot
primitive, and the crate cannot know which fault signal an access will raise
without first attempting the access. Enforcement therefore belongs at the
sampling integration boundary.

## Supported architectures

- x86_64
- aarch64

## License

Apache-2.0
