# pyroscope-kinda-safe

Signal-safe memory reading for x86_64 and aarch64 on Linux and macOS.

This workspace contains two crates:

- [`kindasafe`](kindasafe/) — core read primitives using naked assembly with crash recovery
- [`kindasafe_init`](kindasafe_init/) — signal handler initialization

## Recovery preconditions

Fault recovery is not unconditional. It requires a successfully initialized
recovery handler for SIGSEGV and SIGBUS, handlers that have not been replaced,
and both signals unblocked on the thread performing the read. Signal masks are
inherited by nested signal handlers, so a profiling callback that interrupts a
handler which temporarily blocks SIGSEGV/SIGBUS cannot recover from an
inaccessible-address read. Sampling integrations should call
`kindasafe_init::recovery_available()` at the start of each sample and skip the
read when it reports an error.

See [`kindasafe/README.md`](kindasafe/README.md) for the full precondition
list, initialization guidance, and limits of runtime enforcement.

## License

Apache-2.0
