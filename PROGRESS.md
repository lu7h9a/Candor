# PROGRESS

## Current state
Updated: 2026-11-13 06:05 IST
Milestone: M0   Current WP: WP01 Scaffold   Status: IN_PROGRESS
Next action: create the Cargo workspace, Makefile, CI and private GitHub repo (WP01)
Open questions for owner: Q1
Tree state: clean after WP00 commit
Last green gate: none yet

## WP status
| WP | Name | Status | Verified on | Commit | Notes |
|---|---|---|---|---|---|
| WP00 | Preflight | BLOCKED(E1) | host (non-root parts) | see log | Verify PASS; apt package install pending Q1 (no passwordless sudo) |
| WP01 | Scaffold | IN_PROGRESS | | | |
| WP02 | Protocol crate | TODO | | | |
| WP03 | VM harness | TODO | | | |
| WP04 | BPF skeleton + lifecycle | TODO | | | needs root (Q1) |
| WP05 | Ground-truth workload + harness | TODO | | | needs root (Q1) |
| WP06 | File events | TODO | | | needs root (Q1) |
| WP07 | Network events | TODO | | | needs root (Q1) |
| WP08 | Syscall stats | TODO | | | needs root (Q1) |
| WP09 | Follow mode + budgets | TODO | | | needs root (Q1) |
| WP10 | /proc sampler + identity | TODO | | | needs root (Q1) |
| WP11 | Core state | TODO | | | |
| WP12 | Daemon assembly | TODO | | | needs root (Q1) |
| WP13 | CLI | TODO | | | |
| WP14 | Overhead benchmarks | TODO | | | needs root (Q1) |
| WP15 | Rule engine | TODO | | | |
| WP16 | Rules R001-R004, R012 | TODO | | | |
| WP17 | Rules R005-R008 | TODO | | | |
| WP18 | False-positive evaluation | TODO | | | |
| WP19 | GUI model + transport | TODO | | | |
| WP20 | GUI views | TODO | | | |
| WP21 | Follow UX, loss, robustness | TODO | | | |
| WP22 | Decoys + manifest | TODO | | | |
| WP23 | Launcher | TODO | | | |
| WP24 | Trace integration, differ, report, UI | TODO | | | |
| WP25 | Adversarial suite | TODO | | | |
| WP26 | Real-sample protocol | TODO | | | |
| WP27 | Act mode (experimental) | TODO | | | |
| WP28 | R009, R011, R100 | TODO | | | |
| WP29 | Hardening | TODO | | | |
| WP30 | Packaging | TODO | | | |
| WP31 | Distro matrix | TODO | | | |
| WP32 | Release automation | TODO | | | |
| WP33 | Docs and rename | TODO | | | |
| WP34 | Final audit | TODO | | | |

## Decisions made without the owner
- 2026-11-13 setup: the folder the kickoff named `/home/lu7h9a/project-new` existed as `/home/lu7h9a/project new ` (space, trailing space); renamed it to `project-new` because Makefiles break on paths with spaces - to reverse: `mv ~/project-new "~/project new "`.
- 2026-11-13 setup: moved `KICKOFF_PROMPT.txt` (not in the kickoff's move list) to `docs/KICKOFF_PROMPT.txt` so the repo records how it was started - to reverse: delete it.
- 2026-11-13 WP00: installed rustup with the official installer (plan section 2 authorises it, SKILL.md section 2 exempts it from the curl-pipe ban). It writes to `~/.cargo` and `~/.rustup`, which are not in SKILL.md's write allowlist; plan wins, recorded here. Debian's `/usr/bin/cargo` 1.94.1 is shadowed by prepending `$HOME/.cargo/bin` in the Makefile - to reverse: `rustup self uninstall`.
- 2026-11-13 WP00: system `libbpf-dev` is not installed (Q1), so BPF C is compiled against the libbpf headers vendored in the `libbpf-sys` crate. That is also what libbpf-cargo does, so nothing changes once libbpf-dev is installed.

## Deviations from the plan
- none

## Log
### 2026-11-13 05:58 WP00 Preflight
Did: probed host (kernel, BTF, KVM, VirtualBox, cgroup, systemd, disk, RAM, sysctls), wrote docs/ENV.md, installed rustup stable 1.100.0, compiled a test BPF program. `sudo -n true` fails -> NEEDS_USER Q1 (E1). Available RAM 5453 MiB is under the E5 6 GiB line; re-check at WP03.
Verify command: `rustc --version && clang --version | head -1 && bpftool version | head -1 && qemu-system-x86_64 --version | head -1 && bwrap --version; clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -Iinc -c hello.bpf.c -o hello.bpf.o; file hello.bpf.o`
Verify output (trimmed, real):
```
rustc 1.100.0 (0ef1bc386 2026-11-09)
Debian clang version 21.1.8 (10)
bpftool v7.8.0
QEMU emulator version 10.2.2 (Debian 1:10.2.2+ds-1)
bubblewrap 0.12.0
exit=0
clang exit=0
hello.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), with debug_info, not stripped
```
Result: PASS (verify). WP stays BLOCKED(E1) for the package install half until Q1 is answered.
