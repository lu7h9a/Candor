---
name: sysscope
description: Working rules, architecture invariants, eBPF/Rust pitfalls and exact build/test commands for the SysScope project (Rust + libbpf-rs eBPF process tracer, egui GUI, detection engine, Glasshouse sandbox). Use for ANY task in this repository - writing or changing Rust, BPF C, tests, packaging, docs, or resuming work from PROGRESS.md.
---

# SysScope project skill

You are the sole implementer. The owner is absent. `docs/MASTER_PLAN.md` is the specification, `docs/ESCALATION.md` says when to stop and ask, `PROGRESS.md` is your memory across sessions. Where this file and the plan disagree, the plan wins; record the conflict in PROGRESS.md.

## 1. How to work (non-negotiable)

1. At session start: read `PROGRESS.md`, then the current work package (WP) in `docs/MASTER_PLAN.md`. Never rely on memory of earlier sessions.
2. One WP at a time, in order. Do not start WP n+1 until WP n's verification step passes and is recorded.
3. After each WP: run its Verify command, paste the real command and a trimmed real output into PROGRESS.md, commit, push to the private repo.
4. If a Verify fails: fix the cause. You may not weaken, skip, `#[ignore]`, or rewrite a test to make it pass. After 3 distinct failed fix attempts, follow `docs/ESCALATION.md` (E6) and move to a WP that does not depend on it.
5. Never silently change a decision in the plan's decision record. If evidence shows a decision is wrong, write the evidence in PROGRESS.md and escalate (E6).
6. Claims marked `[VERIFY]` in the plan are the architect's belief, not fact. Check each against the installed kernel/crate before building on it and record the result in `docs/VERIFIED.md` (claim, how checked, result). If false, apply the stated fallback; if none is stated, escalate.
7. Milestone gate (end of M1..M6): run `make gate`; then spawn a fresh subagent with no context, give it only the repo and the invariants in section 3, and instruct it to find violations, security holes and untested behaviour. Fix every confirmed finding, add a regression test for each, re-run `make gate`. Record findings and what remains unverified in `docs/UNVERIFIED.md`.
8. Never claim something works unless you ran it in this session and saw the output.

## 2. Host safety rules (this is the owner's only machine; you have passwordless sudo)

- Never run cargo, rustup or git under sudo. Build as the user, then run the built binary with sudo.
- Write only inside the repo, `/run/sysscope*`, `/var/lib/sysscope*`, `/etc/sysscope*`, `/etc/systemd/system/sysscope*`, and `~/.cache/sysscope-vm`. Anything else: escalate (E7).
- No reboot, no bootloader/kernel-parameter edits, no persistent sysctl changes, no kernel module load/unload, no third-party apt repos, no `curl | sh` except the official rustup installer.
- New or changed BPF programs are loaded in the dev VM first (`make vm-test`), then on the host.
- After every host BPF test run: `sudo dmesg --level=err,warn | tail` and confirm nothing new mentions bpf, BUG, WARNING or RCU. If it does: stop, kill the daemon, escalate (E11).
- Hostile test programs (`testkit/hostile/*`: fork bomb, memory bomb, disk fill, escape probes) run ONLY inside a VM. Never on the host.
- Never download, generate or execute real malware. Tests use only the in-repo simulators.
- Never make the repo public, publish a release, or post anywhere. Private pushes only.

## 3. Architecture invariants (a change that breaks one is wrong by definition)

I1. Two privilege domains. `sysscoped` (root, bounded capabilities) is the only process that loads BPF or reads other users' `/proc`. GUI and CLI are unprivileged and talk only over the Unix socket. The GUI never runs as root; it refuses to start if euid is 0.
I2. BPF programs are observers only. Forbidden helpers: `bpf_probe_write_user`, `bpf_override_return`, `bpf_send_signal*`. No program alters kernel or process behaviour.
I3. No silent loss. Every dropped event is counted at the point of loss (kernel ringbuf, per-tgid budget, client queue) and surfaced in the protocol and UI. Tested identity: emitted = received + counted drops.
I4. Process identity is `ProcKey { tgid, start_ticks }`, never a bare pid, in every map key, struct, message and signal path.
I5. File identity is `(dev, ino)`. Paths are display data: byte strings, possibly truncated or non-UTF-8, never used as identity and never trusted.
I6. Captured metadata only. Never capture read/write buffer contents, environment variables, or keystrokes.
I7. `sysscope-core` is pure: no I/O, no clock, no threads. Time enters as event timestamps. Everything it does is reproducible from a recorded event file.
I8. Bounded everything: every map, queue, ring, buffer, per-process history and client upload has a constant cap and a test that hits the cap.
I9. Detection lives in the daemon. Every finding carries the event ids that justify it. No finding without evidence; no automatic response to a finding, ever.
I10. All bytes that originated in a traced process (paths, argv, comm, addresses) are escaped before they reach a terminal, log, export or report.
I11. The daemon and GUI make zero network connections. Only `AF_UNIX` (and netlink if a library needs it).
I12. The daemon never opens a path supplied by a client. Clients send bytes, not paths.
I13. Glasshouse is never described as safe for real malware, in code, UI text or docs. The exact wording is in the plan (section 6.4).
I14. `unsafe` Rust exists only in `crates/sysscoped/src/abi.rs`. Every other crate has `#![forbid(unsafe_code)]`.

## 4. Do-not-do list (tempting, wrong)

- Do not use tokio/async. Threads plus bounded channels only.
- Do not hook `sys_enter_openat` and read the user pointer for paths (TOCTOU, relative paths). Use the kernel-resolved hook in the plan.
- Do not emit one ring-buffer event per syscall. Syscalls are aggregated in kernel maps.
- Do not filter follow-mode in userspace. The kernel `followed` maps gate emission.
- Do not key anything by pid or by path string.
- Do not parse `/proc/<pid>/stat` by splitting on spaces (comm may contain spaces and parentheses). Use the `procfs` crate or split after the last `)`.
- Do not use `bpf_get_current_comm` as the process name shown to users; it is attacker-controlled. Show the exe path from the exec event.
- Do not use `bpf_probe_read_user_str` return values without checking for negative, and do not ignore truncation; set the truncated flag.
- Do not write unbounded loops or variable-offset accesses without an explicit mask/bound the verifier can see.
- Do not hand-roll namespaces, pivot_root or setuid switching in Rust. Glasshouse uses bubblewrap + a systemd transient unit.
- Do not let the GUI or CLI edit allowlists or rules through the socket.
- Do not add SQLite, gRPC, D-Bus APIs, a web UI, Windows/macOS support, kernel modules, telemetry, auto-update or crash upload.
- Do not add a "stealth" or "hide" option of any kind.
- Do not follow symlinks or open non-regular files when reading a sandbox run directory from the host.
- Do not relax a benchmark or false-positive threshold. Optimise with the listed levers, then escalate with numbers.
- Do not use `unwrap()`, `expect()`, `panic!` or unchecked indexing on external data outside tests.
- Do not write Rust macros, custom derive, trait objects with lifetimes, or generic abstractions "for later". The owner will learn Rust from this code: plain structs, enums, `match`, owned data, small functions.

## 5. Coding conventions

- Rust stable, edition as installed by rustup; pin with `rust-toolchain.toml`. Commit `Cargo.lock`.
- Errors: `thiserror` enums in library crates, `anyhow` only in `main.rs` of binaries.
- Clippy: `-D warnings` plus `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic` denied outside `#[cfg(test)]`.
- Every public type and function has a one-line doc comment saying what it is for. Every module starts with a 3-6 line comment explaining its role, written for a reader new to Rust.
- Prefer `clone()` over lifetime parameters in public APIs. Performance-critical exceptions need a comment with a measurement.
- BPF C: one file per concern under `crates/sysscoped/bpf/`, shared `sysscope.h` for ABI structs, `_Static_assert(sizeof(...))` for every struct that crosses to Rust, matched by a Rust const assertion in `abi.rs`.
- BPF license string: `"Dual MIT/GPL"`. Rust crates: MIT.
- Constants (map sizes, caps, thresholds) live in one place per side: `sysscope.h` and `sysscope-core/src/limits.rs`.
- Commit messages: `WPnn: <what>`; one WP may have several commits.
- User-facing text: plain English, no "malware detected" phrasing. Use "flagged", "suspicious behaviour", "consistent with".

## 6. Exact commands (WP01 creates the Makefile that implements these; keep the names stable)

| Purpose | Command |
|---|---|
| Install pre-authorised toolchain/deps | `make setup` |
| Build everything | `make build` |
| Unit, property, replay, GUI-model and kittest tests (no root, headless) | `make test` |
| Root integration tests on this host | `make test-root` |
| Format + clippy + BPF format check | `make lint` |
| Overhead benchmarks with pass/fail | `make bench` |
| Boot dev VM, copy build, run root tests inside | `make vm-test DISTRO=debian12` |
| All distros | `make vm-matrix` |
| GUI screenshot under Xvfb from replay data | `make gui-shot` (writes `target/shots/*.png`; open them with your image reader and describe what you see in PROGRESS.md) |
| Fuzz targets, 10 min each | `make fuzz` |
| Sandbox adversarial suite (VM only) | `make vm-hostile` |
| False-positive evaluation on the benign corpus | `make fp-eval` |
| Packages | `make package` |
| Milestone gate (lint + test + test-root + bench + vm-test) | `make gate` |
| Run daemon in dev mode | `sudo ./target/debug/sysscoped --dev` |
| Run CLI | `./target/debug/sysscope status` |
| Run GUI | `./target/debug/sysscope-gui` |

`make test-root` must build as the user and run test binaries through `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E"`, never `sudo cargo`.

## 7. eBPF pitfalls (read before touching `bpf/`)

- `bpf_get_current_pid_tgid()`: upper 32 bits = tgid (what users call PID), lower 32 = thread id. Mixing them up is the most common bug.
- IDs are init-namespace values. The daemon must run in the init pid namespace; assert this at startup.
- CO-RE: read kernel struct fields only via `BPF_CORE_READ` family or direct typed access in BTF-typed programs. Never hard-code offsets. Guard optional fields with `bpf_core_field_exists`.
- fentry/fexit/tp_btf argument lists must match the running kernel's function signature. Before attaching to any kernel function, confirm its prototype with `bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -n '<func>'` on the host AND in each matrix VM. If prototypes differ across the matrix, use the fallback in the plan.
- `bpf_d_path` is only legal in specific attach points. A verifier rejection mentioning it means the hook is not on the allowlist for that kernel.
- Ring buffer: always check `bpf_ringbuf_reserve` for NULL, increment the drop counter, return. Every reserve has exactly one submit or discard on every path.
- Per-CPU scratch map for anything larger than ~256 bytes; BPF stack is 512 bytes total.
- Loops: constant upper bound, minimum supported kernel is 5.15 (no `bpf_loop`).
- Strings: fixed-size buffers, explicit length, never assume NUL termination on the Rust side.
- Kernel threads have no mm and no exe; skip them in file/net hooks, label them in process lists.
- Hot paths (`raw_tp/sys_enter`, `vfs_read`, `vfs_write`): first instructions must be the cheap gate (mode + followed lookup). No ring-buffer output from them.
- Use `bpf_ktime_get_boot_ns()` for all timestamps.
- Attach failures of an optional probe degrade gracefully: record the missing feature in the daemon's capability list. Required probes failing = daemon exits with a clear message.

## 8. Where to look things up (never trust memory for APIs)

- Crate APIs: `cargo doc --no-deps -p <crate> --open` is not available headless; read sources under `~/.cargo/registry/src/*/<crate>-<version>/` and examples there. Version = what `Cargo.lock` says.
- libbpf-rs/libbpf-cargo usage: the crate's `examples/` directory in the registry source, and the libbpf-bootstrap repository's Rust examples.
- Kernel types and function prototypes: `/sys/kernel/btf/vmlinux` via `bpftool btf dump`. Tracepoint formats: `/sys/kernel/tracing/events/<cat>/<name>/format` (root).
- BPF helper availability: `bpftool feature probe kernel`. Helper docs: `man bpf-helpers`.
- Syscalls and procfs: `man 2 <name>`, `man 5 proc`, `man 7 capabilities`, `man 7 namespaces`, `man 7 cgroups`.
- bubblewrap: `man bwrap` for the installed version. systemd properties: `man systemd.exec`, `man systemd.resource-control`, `man systemd-run`.
- egui: registry source of `egui`, `eframe`, `egui_plot`, `egui_extras`, `egui_kittest`, and their `examples/`.
- If the web is available, prefer docs.rs for the exact locked version, docs.ebpf.io, and kernel.org Documentation.

## 9. Resuming after interruption

Read PROGRESS.md "Current state" block. Run `git status` and `make build`. If the tree is dirty and PROGRESS.md does not explain it, stash it under a named stash and note that in PROGRESS.md before continuing.
