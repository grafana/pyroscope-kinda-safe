# pyroscope-kinda-safe

Signal-safe memory reading for x86_64 and aarch64 on Linux.

This workspace contains two crates:

- [`kindasafe`](kindasafe/) — core read primitives using naked assembly with crash recovery
- [`kindasafe_init`](kindasafe_init/) — signal handler initialization

In normal builds, initialize recovery before unwinding, keep its SIGSEGV/SIGBUS
handlers installed, and leave both signals unblocked on the reading thread.
Recovered faults return errors to protect the target application from unwinder
bugs. `kindasafe::recovered_faults()` exposes their cumulative count for export
through the profiler's metrics system. Deliberate sanity checks are excluded.
Successful reads still load memory directly without syscalls.

ASan builds use compiler-instrumented Rust loads without assembly or recovery.
Initialization leaves signal handlers untouched, sanity checks skip their
invalid reads, and the fault counter stays zero. Invalid accesses are left to
ASan or fatal-signal handling so recovery cannot hide unwinder bugs. No manual
poison checks or reporter calls are used.

ASan reads require initialized source bytes, valid Rust pointer/aliasing rules,
and no concurrent writes or deallocation during inspection. We accept ASan's
standard fatal reporting inside SIGPROF because these builds diagnose unwinder
bugs and invalid reads are test failures. Reporting is best-effort and can
deadlock; fault tests use subprocess timeouts. See the
[kindasafe documentation](kindasafe/) for the read contracts and reporting limits.

## License

Apache-2.0
