# pyroscope-kinda-safe

Signal-safe memory reading for x86_64 and aarch64 on Linux.

This workspace contains two crates:

- [`kindasafe`](kindasafe/) — core read primitives using naked assembly with crash recovery
- [`kindasafe_init`](kindasafe_init/) — signal handler initialization

## License

Apache-2.0
