# THREAD_DB

[![Latest Version]][crates.io] [![Docs badge]][docs.rs]

[Latest Version]: https://img.shields.io/crates/v/thread_db.svg
[crates.io]: https://crates.io/crates/thread_db

[Docs badge]: https://img.shields.io/badge/docs.rs-rustdoc-green
[docs.rs]: https://docs.rs/thread_db/

[![test](https://github.com/godzie44/thread_db/actions/workflows/test.yml/badge.svg)](https://github.com/godzie44/thread_db/actions/workflows/test.yml)

Rust wrapper for libthread_db (library of interfaces for monitoring and manipulating threads-related aspects of multithreaded programs)

This lib is a wrapper on the glibc implementation. Look at tests for examples.

Supported targets:

| target              | status                                                  |
| ------------------- | ------------------------------------------------------- |
| `x86_64-linux-gnu`  | full                                                    |
| `aarch64-linux-gnu` | full library API; `td_ta_map_lwp2thr` for the main-thread LWP returns `TD_NOTHR` (glibc nptl_db quirk, not a wrapper bug) |

Build / test (any host with Docker + EarthBuild):

```sh
earth +check
earth +check --BS_PLATFORM=linux/amd64
earth -P +test  # full test suite, requires --privileged for ptrace
```
