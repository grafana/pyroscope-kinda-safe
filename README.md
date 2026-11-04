# pyroscope-kinda-safe

Signal-safe memory reading for x86_64 and aarch64 on Linux.

This workspace contains two crates:

- [`kindasafe`](kindasafe/) — core read primitives using naked assembly with crash recovery
- [`kindasafe_init`](kindasafe_init/) — signal handler initialization

Initialize recovery before unwinding, keep its SIGSEGV/SIGBUS handlers installed,
and leave both signals unblocked on the reading thread. Reads report faulting
addresses in ASAN builds after recovery returns. The deliberate protected-page
`sanity_check` also reports when called under ASAN; dedicated ASAN tests verify
recovery in that configuration. Successful reads still load memory directly
without syscalls.

## License

Apache-2.0
