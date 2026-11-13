# PROGRESS

## Current state
Updated: 2026-11-13 06:05 IST
Milestone: M0   Current WP: WP04 BPF skeleton + lifecycle   Status: IN_PROGRESS
Next action: unpack libelf/libzstd dev files into target/sysroot (scripts/sysroot.sh), build the BPF skeleton, verify in the debian12 VM
Open questions for owner: Q1, Q2
Tree state: clean after WP00 commit
Last green gate: none yet

## WP status
| WP | Name | Status | Verified on | Commit | Notes |
|---|---|---|---|---|---|
| WP00 | Preflight | BLOCKED(E1) | host (non-root parts) | see log | Verify PASS; apt package install pending Q1 (no passwordless sudo) |
| WP01 | Scaffold | DONE | host + GitHub CI | WP01 commit | CI run 43337978651 green; libbpf dep deferred to WP04 (needs libelf-dev, Q1) |
| WP02 | Protocol crate | DONE | host | | | |
| WP03 | VM harness | DONE | debian12, ubuntu2204, ubuntu2404 | WP03 commit | fedora/arch refused by E5 RAM guard (Q2), in UNVERIFIED.md |
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

- 2026-11-13 WP03: E5 says "free RAM below 6 GB"; read as 6 GB decimal = 5722 MiB of MemAvailable, enforced in vm/lib.sh (also >= guest RAM + 2 GiB) - asked to relax it in Q2 - to reverse: edit preflight_kvm.
- 2026-11-13 WP03: cloud-init seed ISO is built with genisoimage (cloud-localds is not installed) - standard equivalent, volume id cidata.
- 2026-11-13 WP02: plan 4.5 leaves the JSON shape of `Event.kind` open; chose an object tagged by `"k"` (`"kind":{"k":"Open","path":...}`) - readable with socat/jq - pinned by fixtures/proto/v1.
- 2026-11-13 WP02: plan names `FileStat`, `ConnStat`, `SysStat`, `MapRow`, `GhReport` without fields; defined them from plan 6.3 and 4.3 (see crates/sysscope-proto/src/types.rs). Adding fields later is additive (no proto bump).
- 2026-11-13 WP02: Rust field `ProcKey.start_ticks` is sent as `"start"` on the wire, matching 4.5 while keeping the I4 name in code.
- 2026-11-13 WP02: the 4.5 escaping leaves valid-UTF-8 C1 controls (U+0080-U+009F) and bidi overrides (U+202A-U+202E, U+2066-U+2069) unescaped. Wire format kept exactly as specified; terminal/GUI display code must additionally neutralise these (to do in WP13/WP20, tracked in docs/UNVERIFIED.md once it exists).

## Deviations from the plan
- 2026-11-13 WP03: plan says images are verified by SHA256 -> Debian only publishes SHA512SUMS for its cloud images, so debian12 is verified with SHA-512; the others with SHA-256 - published checksum files, fetched over HTTPS from the official origin - allowed: the intent (verify against the published checksum) is met

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

### 2026-11-13 06:10 WP01 Scaffold
Did: Cargo workspace with the 7 crates from plan 4.1 as stubs (edition 2024, toolchain pinned to 1.100.0), Makefile with every SKILL.md section 6 target (targets for later WPs exit 1 with "not implemented yet (WPnn)"), clippy config (unwrap/expect/panic denied outside tests), LICENSE, .gitignore, deny.toml, `.github/workflows/ci.yml` (ubuntu-24.04, `make lint test`), `scripts/check-integrity.sh` (fails on `#[ignore]`, and on a modified threshold file without a new Deviations line). Created private repo lu7h9a/sysscope. The `sysscoped` crate does not depend on libbpf-rs yet: libbpf-sys needs libelf-dev headers (or autopoint+bison for its vendored libelf), all missing until Q1; WP04 adds the dependency.
Verify command: `make build && make lint && make test` then `gh run watch 43337978651 --exit-status`; integrity negatives tested in a scratch clone.
Verify output (trimmed, real):
```
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.31s
lint: no BPF C files yet
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
--- integrity script, scratch clone ---
integrity: OK                      (create limits.rs) exit=0
integrity: threshold file(s) changed since HEAD~1 without a new
'## Deviations from the plan' entry in PROGRESS.md: crates/sysscope-core/src/limits.rs   exit=1
integrity: OK                      (same change + Deviations line) exit=0
integrity: ignored tests are not allowed: ./crates/sysscope-core/src/x.rs:2:#[ignore]   exit=1
--- CI ---
✓ main ci · 43337978651   ✓ lint-test in 28s
```
Result: PASS

### 2026-11-13 06:40 WP02 Protocol crate
Did: `sysscope-proto` with all 4.5 types (serde, internally tagged by "t"), `BStr` reversible escaping, `read_frame`/`write_frame` with 1 MiB / 16 MiB limits checked before allocation, finite-f32 clamping, decode that separates `unknown_type` from `malformed`, golden JSON for all 21 message types in fixtures/proto/v1, proptests (2000 cases for round trips, 10 000 for hostile frame input).
Verify command: `cargo test -p sysscope-proto`
Verify output (trimmed, real):
```
test result: ok. 8 passed; 0 failed; 0 ignored (unit: bstr, frame)
test every_message_type_has_exactly_one_golden_file ... ok
test client_messages_match_golden_files ... ok
test daemon_messages_match_golden_files ... ok
test unknown_type_and_malformed_are_distinguished ... ok
test non_finite_floats_are_clamped ... ok
test oversized_frames_are_errors ... ok
test framed_messages_roundtrip ... ok
test client_messages_roundtrip ... ok
test bstr_roundtrips_any_bytes ... ok
test garbage_never_panics ... ok          (10 000 cases)
test daemon_messages_roundtrip ... ok
test truncated_frames_are_errors ... ok   (10 000 cases)
test result: ok. 11 passed; 0 failed; 0 ignored; finished in 1.57s
```
`make lint` and `make test` green.
Result: PASS

### 2026-11-13 06:42 WP03 VM harness
Did: vm/lib.sh, up.sh, run.sh, down.sh. Images cached in ~/.cache/sysscope-vm/images and verified against the distro's published checksum file; per-boot qcow2 overlay plus `-snapshot`; cloud-init seed (genisoimage) creates user `sysscope` with a fresh ed25519 key and /etc/sysscope-test-vm; SSH forwarded on 127.0.0.1 only; KVM required; refuses if a VirtualBox VM runs or free RAM is under the E5 line. run.sh copies target/release/sysscope* into /opt/sysscope/bin and runs the command as root, returning its exit code.
Verify command: `vm/run.sh <distro> 'uname -r && test -f /sys/kernel/btf/vmlinux && echo OK'` for each distro
Verify output (trimmed, real):
```
vm: downloading https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2
vm: debian12 up
6.1.0-54-amd64
OK                      rc=0
=== ubuntu2204
5.15.0-203-generic
OK                      rc=0
=== ubuntu2404
6.8.0-147-generic
OK                      rc=0
=== fedora
vm: only 5616 MiB RAM available; need 5722 (escalate E5)   rc=1   (retry: 5194 MiB)
=== arch
vm: only 5614 MiB RAM available; need 5722 (escalate E5)   rc=1   (retry: 5188 MiB)
```
Result: PASS for debian12 (the hard requirement) and both Ubuntu releases. fedora/arch not booted: E5 guard, NEEDS_USER Q2, recorded in docs/UNVERIFIED.md.
