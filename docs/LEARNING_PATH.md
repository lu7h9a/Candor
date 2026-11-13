# LEARNING_PATH.md - Rust for this codebase only

For Anshul. You chose to ship first and learn after, so this path is a reading order through the finished code, with the minimum Rust needed at each stop. You already know C and C++, which covers about half of it.

Chapter names refer to "The Rust Programming Language" (the official Rust Book). Chapter numbers have shifted between editions, so go by title.

## Resources (only these)

- The Rust Book (official): https://doc.rust-lang.org/book/
- Rust by Example (official): https://doc.rust-lang.org/rust-by-example/
- Rustlings (official exercises): https://github.com/rust-lang/rustlings
- Comprehensive Rust (Google's course, free): https://google.github.io/comprehensive-rust/
- Jon Gjengset, "Crust of Rust" (YouTube) - only the two episodes named below
- egui docs and live demo: https://docs.rs/egui and https://www.egui.rs
- "Learning eBPF" by Liz Rice (O'Reilly) - chapters on CO-RE and on tracing program types
- Andrii Nakryiko's blog, "BPF CO-RE reference guide": https://nakryiko.com
- eBPF docs: https://docs.ebpf.io
- libbpf-bootstrap repository (the Rust examples): https://github.com/libbpf/libbpf-bootstrap

## Stage 1 - Read `sysscope-proto` (2 evenings)

Code: plain data types and their JSON form.

1. Variables, mutability, shadowing - Book: "Common Programming Concepts".
2. Ownership, moves, borrowing with `&` and `&mut` - Book: "Understanding Ownership". This is the one chapter to read slowly. C++ link: a move is `std::move` by default, and the compiler enforces no-use-after-move.
3. `String` vs `&str`, `Vec<T>` vs `&[T]` - Book: "Common Collections" (strings and vectors only).
4. Structs and `impl` blocks - Book: "Using Structs to Structure Related Data".
5. Enums with data and `match` - Book: "Enums and Pattern Matching". This is how every event and message type is written.
6. `Option<T>` and `Result<T, E>`, the `?` operator - Book: "Error Handling".
7. `#[derive(...)]` as a thing you use, not write - Rust by Example: "Derive". For serde, read only the serde.rs "Using derive" page.

Exercise: add a new field to `ProcRow`, run the tests, read the golden-file failure, fix it.
Rustlings: variables, functions, move_semantics, structs, enums, strings, options, error_handling.

## Stage 2 - Read `sysscope-core` (3 evenings)

Code: the process table, rules, scoring. Pure logic, no I/O.

8. Modules, `pub`, `use`, crates and workspaces - Book: "Managing Growing Projects" and the "Cargo Workspaces" section.
9. `HashMap`, `VecDeque`, `BTreeMap` - Book: "Common Collections" (hash maps); std docs for `VecDeque`.
10. Iterators and closures: `iter()`, `map`, `filter`, `collect`, `sum` - Book: "Functional Language Features". Learn to read chains; you do not need to write clever ones.
11. Traits as interfaces (using `Display`, `Default`, `From`) - Book: "Traits: Defining Shared Behavior" only. C++ link: like a concept or an abstract base with no data.
12. Tests: `#[test]`, `assert_eq!`, `cargo test` - Book: "Writing Automated Tests".

Exercise: write a new rule fixture (a JSONL file) that should trigger R002, add its expected output, run the replay test. Then change the R007 threshold in `rules.toml` and watch the boundary fixture fail.
Rustlings: modules, hashmaps, iterators, traits, tests.

## Stage 3 - Read `sysscoped` without `abi.rs` and `bpf/` (3 evenings)

Code: threads, channels, the socket server, the /proc sampler.

13. Threads and `move` closures - Book: "Fearless Concurrency", thread section.
14. Channels (message passing) - same chapter. The daemon uses `crossbeam-channel`; the concept is identical to `std::sync::mpsc`.
15. `Arc` and why the code mostly avoids `Mutex` (one thread owns the state) - same chapter, shared-state section; skim.
16. `std::io::Read` / `Write`, Unix sockets - std docs for `std::os::unix::net`.
17. `anyhow` in `main`, `thiserror` in libraries - each crate's README is enough.

Video: Jon Gjengset, Crust of Rust: "Channels".
Exercise: add a `Ping` counter to the daemon's status output.

## Stage 4 - Read `bpf/*.c`, then `abi.rs` and `build.rs` (3 evenings)

This is mostly C, your home ground. The Rust part is small.

18. eBPF concepts: program types, maps, verifier, ring buffer - Liz Rice, "Learning eBPF", the CO-RE chapter and the chapter on program and attachment types; docs.ebpf.io for each helper used.
19. CO-RE and `vmlinux.h` - Nakryiko's CO-RE reference guide.
20. `#[repr(C)]`, raw bytes to struct, and what `unsafe` promises - Book: "Unsafe Rust" (first half only). Read `abi.rs` line by line; it is the only unsafe file.
21. Build scripts - Cargo Book: "Build Scripts" (first page), then read `build.rs`.

Exercise: add a `gid` field to the event header on both sides and make the size assertions pass. Run the root tests in the VM.

## Stage 5 - Read `sysscope-gui` (2 evenings)

22. Immediate-mode GUI idea - egui README "How it works" and the live demo source for tables and plots.
23. Read `model.rs` first (plain Rust you already know), then one view file.
24. Lifetimes: only enough to read `&'a` in a function signature - Book: "Validating References with Lifetimes", first two sections.

Video: Jon Gjengset, Crust of Rust: "Lifetime Annotations" (first 30 minutes).
Exercise: add a column to the process table.

## Stage 6 - Read `sysscope-glasshouse` and `docs/THREAT_MODEL.md` (2 evenings)

No new Rust. Read `man 7 namespaces`, `man 7 cgroups`, `man bwrap`, `man 2 seccomp` alongside the launcher. Then run the demo in the VM and match each line of the report to the code that produced it.

## Deliberately skip (not used in this codebase)

async/await, tokio, futures; writing macros (`macro_rules!`, proc macros); advanced traits (associated types beyond reading, GATs, trait objects with lifetimes); generics beyond reading `Vec<T>` and `Option<T>`; `Rc`, `RefCell`, `Cell`, `Pin`; smart-pointer internals; `Box<dyn Trait>` patterns beyond recognising them; FFI and `extern "C"`; `no_std`; const generics; operator overloading; the borrow checker's corner cases (Polonius, variance); Rust-side eBPF (Aya); wgpu and shaders; web/WASM.

## Interview readiness check

You are ready to present this project when you can answer, without notes: why the GUI is not root; what happens when the ring buffer is full; why a pid is not an identity; why paths are not trusted; what the detector cannot see; why Glasshouse is not safe for real malware; and which one file contains `unsafe` and why.
