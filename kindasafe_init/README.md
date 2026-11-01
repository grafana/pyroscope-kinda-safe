# kindasafe_init

Signal handler initialization for the [kindasafe](https://crates.io/crates/kindasafe) signal-safe memory reading library.

Installs SIGSEGV and SIGBUS signal handlers that enable `kindasafe` to recover from memory access faults instead of crashing. Preserves any previously installed signal handlers as fallbacks.

## Usage

```rust
use kindasafe_init::{init, recovery_available};

init().expect("failed to initialize kindasafe");

// Check at the boundary of each sampling callback. This is especially
// important when the callback may run with SIGSEGV or SIGBUS blocked.
if recovery_available().is_ok() {
    let result = kindasafe::u64(some_address);
}
```

## Recovery preconditions

Fault recovery requires all of the following:

1. `init()` completed successfully.
2. SIGSEGV and SIGBUS still point at kindasafe's handlers. Handlers installed by
   another component after `init()` replace kindasafe's handlers.
3. The reading thread has both SIGSEGV and SIGBUS unblocked.
4. No interrupted signal handler has temporarily blocked either fault signal on
   that thread. A nested signal handler inherits the interrupted thread's mask,
   so this includes profiling callbacks that interrupt a handler which blocks
   SIGSEGV/SIGBUS.

Blocking a synchronous fault signal prevents recovery. On Linux, faulting while
SIGSEGV or SIGBUS is blocked normally terminates the process with the default
action; the handler is not run. `init()` does not alter thread signal masks and
cannot make a blocked signal recoverable.

`recovery_available()` is a lock-free, non-mutating check for the current
thread. It verifies initialization, the installed handlers, and the blocked
mask. Call it at the start of a sampling callback and skip the read on any
error:

```rust
match kindasafe_init::recovery_available() {
    Ok(()) => { /* safe to attempt a potentially-faulting read now */ }
    Err(reason) => { /* skip this sample; reason explains why */ }
}
```

The check is best-effort: another thread can replace a handler, or code can
change the mask, between the check and the read. Do not unblock SIGSEGV/SIGBUS
from inside a profiling handler just to make a read work; that changes the
application's signal semantics. If a profiling handler uses `sa_mask`, do not
include SIGSEGV or SIGBUS in it.

## Limitations

`kindasafe_init` can only install process-wide handlers. It cannot enforce that
application code keeps them installed or keeps fault signals unblocked on every
thread. Those are caller/integration responsibilities. The core `kindasafe`
crate deliberately performs no per-read platform signal-mask syscall; use
`recovery_available()` once per sample instead.

## License

Apache-2.0
