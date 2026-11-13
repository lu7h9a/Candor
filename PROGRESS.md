# PROGRESS

## Current state
Updated: 2026-11-13 06:05 IST
Milestone: M4   Current WP: WP16-WP18 (root parts)   Status: IN_PROGRESS
Next action: unblocked root parts of WP16-WP18 (simulator end-to-end for R001-R008/R012, R006 with the Q3 test override, fp-eval benign corpus incl. R009/R011), then WP29
Open questions for owner: Q4 (2026-11-14: Q1 A passwordless sudo, Q2 A 4 GiB VM line, Q3 A test-only R006 override)
Tree state: clean after WP00 commit
Last green gate: none (gate needs `make test-root` on the host = Q1). Gate slice M1/M2 (lint + test + VM itests + adversarial review, all findings fixed) green 2026-11-13 on debian12/ubuntu2204

## WP status
| WP | Name | Status | Verified on | Commit | Notes |
|---|---|---|---|---|---|
| WP00 | Preflight | BLOCKED(E1) | host (non-root parts) | see log | Verify PASS; apt package install pending Q1 (no passwordless sudo) |
| WP01 | Scaffold | DONE | host + GitHub CI | WP01 commit | CI run 43337978651 green; libbpf dep deferred to WP04 (needs libelf-dev, Q1) |
| WP02 | Protocol crate | DONE | host | | | |
| WP03 | VM harness | DONE | debian12, ubuntu2204, ubuntu2404 | WP03 commit | fedora/arch refused by E5 RAM guard (Q2), in UNVERIFIED.md |
| WP04 | BPF skeleton + lifecycle | BLOCKED(E1) | debian12 | WP04 commit | debian12 verify PASS; host pending Q1; ubuntu2204 refused by E5 guard |
| WP05 | Ground-truth workload + harness | BLOCKED(E1) | debian12 | WP17 commit | debian12 itests 5/5 PASS; host `make test-root` pending Q1 |
| WP06 | File events | BLOCKED(E1) | debian12, ubuntu2204 | WP06-08 commit | VM verify PASS on 6.1 and 5.15; host pending Q1 |
| WP07 | Network events | BLOCKED(E1) | debian12, ubuntu2204 | WP06-08 commit | VM verify PASS on 6.1 and 5.15; host pending Q1 |
| WP08 | Syscall stats | BLOCKED(E1) | debian12, ubuntu2204 | WP09 commit | count exact, followed nanosleep latency in range; host pending Q1 |
| WP09 | Follow mode + budgets | BLOCKED(E1) | debian12, ubuntu2204 | WP09 commit | follow + loss identity PASS on 6.1/5.15; host pending Q1 |
| WP10 | /proc sampler + identity | BLOCKED(E1) | debian12, ubuntu2204 | WP10 commit | 200/200 ProcKey equal, CPU and RSS checks PASS; host pending Q1 |
| WP11 | Core state | DONE | host | WP11 commit | 1M-event replay 14.25 s, peak RSS 80 MB |
| WP12 | Daemon assembly | BLOCKED(E1) | debian12, ubuntu2204 | WP12 commit | all server itests + 10-min RSS (118 MiB) PASS; host pending Q1 |
| WP13 | CLI | DONE | debian12 (root itests) + host (unit) | WP13 commit | host-side runs need the daemon: VM only until Q1 |
| WP14 | Overhead benchmarks | BLOCKED(E1) | | | thresholds are defined for the host; needs root |
| WP15 | Rule engine | DONE | host | WP15 commit | worked example = 72 |
| WP16 | Rules R001-R004, R012 | BLOCKED(E1) | host (fixtures) | WP16 commit | 40 replay fixtures PASS; simulator end-to-end needs the live daemon (WP12, root) |
| WP17 | Rules R005-R008 | BLOCKED(E1) | host (fixtures) | WP17 commit | 36 new fixtures PASS; simulator end-to-end needs live daemon; R006 simulator conflict noted |
| WP18 | False-positive evaluation | BLOCKED(E1) | | | needs recordings from the live daemon (WP12, root) |
| WP19 | GUI model + transport | DONE | host | WP19 commit | 9 unit tests (model + net) |
| WP20 | GUI views | DONE | host (Xvfb + kittest) | WP20 commit | 6 screenshots described below |
| WP21 | Follow UX, loss, robustness | DONE | host (Xvfb, fake daemon) | WP21 commit | GUI threads 6-7 % CPU, 125 MiB; real-GPU check left to the owner |
| WP22 | Decoys + manifest | DONE | host | WP22 commit | 42 decoys per plan 6.2 |
| WP23 | Launcher | BLOCKED(E1) | debian12 (available), ubuntu2404 (correctly unavailable) | WP23 commit | host run pending Q1 |
| WP24 | Trace integration, differ, report, UI | BLOCKED(E1) | debian12 + ubuntu2204 exact demo report and attribution; ubuntu2404 correctly unavailable | WP24 commit | host run pending Q1 |
| WP25 | Adversarial suite | DONE | 20/20 CONTAINED debian12 + ubuntu2204 (after M4 fixes); ubuntu2404 refusal | WP25 + M4 commits | |
| WP26 | Real-sample protocol | DONE | detonate.sh with fake_malware.py zip: full report over serial; network overrides refused | WP26 commit | |
| WP27 | Act mode (experimental) | DONE | 5 act itests + all itests on debian12 and ubuntu2204 | WP27 commit | host run pending Q1 |
| WP28 | R009, R011, R100 | DONE | fixtures 6+6 each; e2e simulators in 2 VMs + host; R100 unit tests | WP28 commit | benign-corpus check runs with WP18 |
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

- 2026-11-13 WP04: libelf-dev, libzstd-dev and clang-format-21 (all pre-authorised, official Kali repo) are unpacked with `apt-get download` + `dpkg-deb -x` into the gitignored target/sysroot by scripts/sysroot.sh, because they cannot be installed without sudo (Q1). Nothing outside the repo is written; apt checks the packages against the signed index. Becomes a no-op once the packages are installed - to reverse: `rm -rf target/sysroot`.
- 2026-11-13 WP04: VM-first verification of BPF WPs uses host-built binaries. The vendored libbpf, compiled against glibc 2.43 headers, references `__isoc23_*` (GLIBC_2.38); crates/sysscoped/compat/glibc_compat.c provides those three entry points via the classic functions so the daemon needs only GLIBC_2.34 and runs on debian12/ubuntu2204. WP30 still builds release packages on the oldest glibc.
- 2026-11-13 WP04: exec path comes from `fentry/security_file_open` (bpf_d_path-legal) for `__FMODE_EXEC` opens, stashed by (tid, dev, ino) and picked up by the `sched_process_exec` tracepoint, because `bpf_d_path` is not allowed in tp_btf programs. Fallback: the execve argument with flag F_PATH_FROM_ARG. Exec also carries the parent's ProcKey (additive to the 4.3 ABI).
- 2026-11-13 WP04: WP04 rows are marked BLOCKED(E1), not DONE: verified in the debian12 VM, host verification waits for Q1. Same pattern for later kernel WPs.

- 2026-11-13 WP11: a live process missing from 2 consecutive full /proc scans is marked exited (its EXIT may have been dropped); evicting a parent sets its children's parent to null and marks them orphan, so "parent exists or null" always holds.
- 2026-11-13 WP11: core inputs and the `*.events.jsonl` line format are `sysscope_core::Input` (`RawEvent`, `Samples`, `Loss`, `Tick`, tagged by "t"); replay streams line by line.

- 2026-11-13 WP15: core input `ExeMeta {proc, trusted, system_dir, home}` carries what the daemon checked about an executable (5.3 ownership condition, R001 confidence, "~/" expansion); a new Exec resets trust until the next ExeMeta.
- 2026-11-13 WP15: path pattern semantics: "*" never crosses "/"; a pattern without "/" matches the file name only (so "*.kdbx" and "wallet.dat" match anywhere). Config files use deny_unknown_fields (the protocol does not).

- 2026-11-13 WP06: RENAME/UNLINK paths: leaf-first NUL-separated dentry walk (<= 16 components, 768-byte buffer so the verifier can bound each 256-byte component copy), mount point from /proc/self/mountinfo by dev (root mount preferred), always marked approx. Preferring a path already seen in an OPEN for the same (dev,ino) is left to the WP12 daemon state.
- 2026-11-13 WP07: CONNECT copies a constant 128 bytes of the kernel sockaddr (the syscall path keeps it in a 128-byte sockaddr_storage) and records min(addrlen,128) as its length: a computed-length copy was rejected by the 6.1 and 5.15 verifiers after clang dropped the mask.
- 2026-11-13 WP09: the budget map value also counts ring-buffer-full drops per tgid (`rb_dropped`), so the loss identity can be checked per process system-wide and ProcRow.ev_dropped can include both reasons.
- 2026-11-13 setup: .cargo/config.toml sets C_INCLUDE_PATH / LIBBPF_SYS_LIBRARY_PATH to target/sysroot (relative) so plain `cargo` works, not only `make`.
- 2026-11-13 WP24: box attribution = the box unit's main pid (stage2, which execs bubblewrap) plus everything forked from it (Fork events in kernel order); no cgroup id in the event header, so no BPF change. The box cgroup id is still put into `followed_cgroup`, so a run is fully traced while the user follows something else (checked: identical report while following an unrelated `sleep`).
- 2026-11-13 WP24: the generated home gets a plain, non-decoy `~/.bashrc`, and the differ gets a full pre-run baseline of non-decoy files. This makes "tries to write ~/.bashrc" reach R004 (an open without O_CREAT on a missing file never reaches security_file_open) while "exactly 1 created" still holds. The changed `.bashrc` is reported as a note ("pre-existing non-decoy file changed").
- 2026-11-13 WP24: the attribution check counts data opens. Under `strace -f` the box makes 134 successful opens, 14 of them O_PATH (bwrap mount setup). O_PATH opens give no access to file data and never reach security_file_open, so the comparison is 120 strace data opens = 120 traced opens. The calibration needs ptrace, which the seccomp filter refuses, so it is a separate `run-local --calibrate` run without the seccomp filters. The daemon has no way to request this mode.
- 2026-11-13 WP24: the sample name, arguments and timeout travel in a job file (`RUNS/<id>.job.json`, then `<run>/job.json`), not on the systemd-run command line, so systemd never expands `$`/`%` in untrusted text. The helper protocol (`sysscope_proto::helper`) uses deny_unknown_fields and a 16 MiB line cap. A report timeline keeps 20 000 events; a report frame over 16 MiB is shrunk by halving the timeline, with a note.
- 2026-11-13 WP24: protocol additions are additive and defaulted, as WP15 did: GhStatus.decoys (live tiles), CreatedFile.kind, GhReport.notes. Goldens GhStatus/GhReport were re-blessed (diff = only those lines); proto stays 1.
- 2026-11-13 WP24: the GUI file picker is an in-window directory browser (no native dialog dependency). Hidden files and names that would need escaping are not listed; any path can still be typed.

## Deviations from the plan
- 2026-11-13 WP21: GUI CPU budget (< 10 % of one core) is measured on the GUI's own threads; under Xvfb, Mesa's llvmpipe threads do the rasterising that a GPU does on real hardware, and the whole process including them uses ~33 %. Real-GPU measurement is a human check (UNVERIFIED.md)
- 2026-11-13 gate: protocol `Loss` gained `decode` (kernel records the daemon could not decode), additive with serde default like `subject`; goldens Snapshot.json/GhReport.json and fixtures/core/basic.snapshot.json regenerated (diff = only the new `"decode": 0` lines) - proto stays 1
- 2026-11-13 gate: BPF maps `budget`, `sys_count`, `sys_lat` are keyed by tgid + start time and `followed_tgid` values carry start ticks checked by the gate (I4). Plan 4.3 lists them keyed by tgid alone; I4 (SKILL.md) forbids bare-pid keys, and pid reuse was a confirmed review finding - plan/SKILL conflict resolved in favour of the invariant, recorded here
- 2026-11-13 WP13: explanations and event times in the CLI are shown in UTC (tz_offset 0): local time zone needs either libc (unsafe) or a zoneinfo parser; noted in docs/UNVERIFIED.md for WP20/WP33
- 2026-11-13 WP12: EXIT is emitted by the first thread that sees signal->live == 0, de-duplicated per (tgid, start) with an LRU map; the VM showed two EXITs when a joined thread was still inside do_exit while the main thread exited - refines the WP04 choice (recorded in VERIFIED.md)
- 2026-11-13 WP06: OPEN events are not emitted for exec-opens (`__FMODE_EXEC`: the binary, its interpreter, ld.so); they feed the exec-path stash and are represented by the EXEC event - plan silent; avoids double counting exec as open
- 2026-11-13 WP17: limits.rs gained MAX_EVIDENCE_IDS (1000), WINDOW_ENTRIES (4096), BEACON_POINTS (64) - new caps required by I8 for finding evidence lists and rule windows; no existing value changed - allowed: plan 4.6 is silent on these
- 2026-11-13 WP17: PLAN CONFLICT (not resolved, recorded): 5.7(2) says network simulators talk only to 127.0.0.0/8 and WP17 specifies `sim/beacon.py` with a local listener, but R006 (5.4) only counts non-loopback destinations, so that simulator cannot trigger R006. Kept R006 exactly as specified; beacon.py is loopback-only as specified; R006 positives are covered by replay fixtures with 10.1.2.3 / 93.184.216.34. The end-to-end R006 check (blocked by Q1 anyway) needs an owner decision or a test-only rules override that allows loopback - raised as NEEDS_USER Q3 (E6).
- 2026-11-13 WP17: R005 "for one process tree" implemented as: each event counts for its process and for that process's direct parent (bounded; avoids flagging systemd for unrelated services). R005 simulator files live in its own dir, so the end-to-end test must add that dir to R005 `roots` via a test rules override (like R004).
- 2026-11-13 WP15: added field `subject` to protocol `Finding` (it is part of the de-duplication key and of the "To silence" allowlist line in 5.6). Plan 4.5 says additive fields do not bump `proto`, and also that changing a golden file requires a bump; treated as additive: `#[serde(default)]` so older peers still decode, goldens Alert/Detail/GhReport.json regenerated (diff = exactly one `"subject"` line each), proto stays 1 - allowed by the additive-field rule
- 2026-11-13 WP11: plan says measure the 1M-event replay with `/usr/bin/time -v` -> the `time` package is not installed and not pre-authorised, so the replay example prints VmHWM from /proc/self/status (the value time -v reports as maximum RSS) and its own wall time - allowed: same measurement, different reader
- 2026-11-13 WP03: plan says images are verified by SHA256 -> Debian only publishes SHA512SUMS for its cloud images, so debian12 is verified with SHA-512; the others with SHA-256 - published checksum files, fetched over HTTPS from the official origin - allowed: the intent (verify against the published checksum) is met
- 2026-11-13 WP25: unit property LimitCORE=1 instead of the plan's LimitCORE=0. With 0, a piped kernel.core_pattern still ran the host's root core handler for box processes (probe ESCAPED, see VERIFIED.md). 1 is the kernel's "no piped dump" value.
- 2026-11-13 WP25: `make vm-hostile` runs debian12, ubuntu2204 and ubuntu2404. On ubuntu2404 no box can start (AppArmor userns restriction, WP23), so there the suite only checks the clean refusal; ubuntu2204 is added so a second kernel is attacked. Hostile probes cannot see /etc/sysscope-test-vm or DMI from inside the box, so in-box guards are hostname "glasshouse" + HOME + uid 1000 + the CPU "hypervisor" flag. The runner (outside the box) checks the marker file and DMI=QEMU before anything starts.
- 2026-11-14 WP28: rules.toml gained R009, R011 and R100 with the plan 5.4 weights and confidences (R009 0.5/0.6, R011 0.6/0.7, R100 0.3/0.5, R100 `disabled = true`). The pattern lists are my choice, since the plan names classes only: R009 `programs` (shells and interpreters), `parents` (viewers, office, browsers, mail, web servers); R011 `debuggers` (gdb, lldb, strace, ltrace, valgrind, rr, perf, sysprof, heaptrack, gcore, uftrace, bpftrace, criu, crash handlers). R100 is evaluated per finished run (at exit), not on a rolling 5-minute window. A run is the natural unit for a per-executable baseline, and long-lived processes are where a rolling window would matter; noted for the owner. No existing threshold changed.

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

### 2026-11-13 07:20 WP04 BPF skeleton + lifecycle
Did: bpf/sysscope.h (ABI, _Static_assert sizes), maps.h, gate.h (ignored + follow gate), lifecycle.bpf.h (exec/fork/exit), file.bpf.h (exec-path stash), vmlinux.h committed with provenance; build.rs (libbpf-cargo skeleton, clang -Wall -Werror); abi.rs (skeleton include, only unsafe; length-checked safe decoding; const size assertions; kernel dev_t -> st_dev); startup checks (root, BTF, init pid ns; exit 3 for no BTF); `sysscoped --dev --dump` prints JSONL and drop counters. EXIT = last thread of the group (signal->live == 0), see VERIFIED.md. Found and fixed: ld.so exec-open overwrote the stash (now keyed by tid+dev+ino). `make vm-test` implemented; `make lint` now checks BPF formatting with clang-format 21.
Verify command: `make release && vm/run.sh debian12 "$(cat vm/tests/wp04_lifecycle.sh)"`
Verify output (trimmed, real):
```
sysscoped: tracing (dump mode); Ctrl-C to stop
sysscoped: received=319 decode_errors=0 dropped ringbuf=0 budget=0 scratch=0
parent=855 total_events=319 FORK=100 EXEC=100 EXEC_exe_ok=100 EXIT=100 expected_exe=/usr/bin/true
sample exec: {"id": 17, ..., "proc": {"tgid": 856, "start": 11653}, ..., "kind": {"k": "Exec", "exe": "/usr/bin/true", "argv": "/bin/true\\x00", "argv_trunc": false, "fileless": false, "dev": 65025, "ino": 689}}
WP04 LIFECYCLE PASS
dmesg: no new bpf/BUG/WARNING/RCU lines
```
`make lint` rc=0; `make test` green (sysscoped: 8 tests incl. I2 forbidden-helper check).
Result: PASS on debian12 (kernel 6.1.0-54). Host: BLOCKED(E1). ubuntu2204: refused by E5 guard (5499 MiB).

### 2026-11-13 07:50 WP05 Ground-truth workload + harness (code; verify pending)
Did: testkit/wl/wl.c (static, raw syscalls, every action in the plan, JSON manifest with tgid/start_ticks and file identities); sysscope-itest lib (`Dump`, `wl`, `run_wl`, `subtree`) and tests/lifecycle.rs (exec 100, fork 100, threads, leader-exits-first, memfd fileless); `make wl`, `make itest-bin` (ships itest binaries to VMs), vm/tests/wp05_itest.sh. Host smoke run of every wl action succeeded (output in session). The root verify could not run: host needs Q1, and the debian12 VM was refused by the E5 guard (5459-5462 MiB available). A background job retries when RAM allows.
Result: PENDING (BLOCKED E1/E5)

### 2026-11-13 08:00 WP11 Core state
Did: sysscope-core: limits.rs (4.6), input.rs (core inputs = recording lines), proc.rs (bounded per-process recent/series/files/conns/syscalls), state.rs (process table, tree with cycle refusal, placeholders, sample-driven CPU%, missed-scan exit, retention and caps, snapshot/detail), replay.rs (streaming, errors with line numbers). Tests: each cap hit with limit+1000, retention, placeholders, orphans, cycles, 500-case property test (no cycles, parent exists or null, child lists consistent, counters equal a naive recount), golden replay fixtures/core/basic.events.jsonl -> basic.snapshot.json (values checked by hand: systemd 10 %, bash 50 % CPU).
Verify command: `cargo test -p sysscope-core` and `python3 scripts/gen_events.py 1000000 target/bench-1m.events.jsonl && target/release/examples/replay_file target/bench-1m.events.jsonl`
Verify output (trimmed, real):
```
test result: ok. 12 passed; 0 failed; 0 ignored   (state.rs incl. property test)
test result: ok. 2 passed; 0 failed; 0 ignored    (replay.rs golden + bad input)
1000000   (RawEvent lines)
procs=5047 live=2999 exited=2048 global_events=100000 stats=StateStats { procs_refused: 0, procs_evicted: 36597, events_unattributed: 0, cycles_refused: 100 }
elapsed_s=14.25 VmHWM:	   80384 kB
```
`make lint` and `make test` green.
Result: PASS (under 20 s and under 300 MiB)

### 2026-11-13 08:30 WP15 Rule engine
Did: crates/sysscope-core/rules.toml (texts, weights, thresholds, path classes for R001-R008, R012) and allow.toml (24 default entries); config.rs (embedded defaults + override merged key by key, schema with deny_unknown_fields, range checks, clear file:line errors); glob.rs (byte-level, "*" within one component); detect.rs (Hit -> Finding with allowlist requiring a trusted exe, de-dup by (rule, proc, subject), MAX_FINDINGS cap, noisy-OR score with 600 s half-life, tree score, bands, alert on first entry to suspicious/high, row annotation); explain.rs (5.6 text, escaped bytes). Proto Finding gained `subject` (see Deviations).
Verify command: `cargo test -p sysscope-core --test detect` (+ config unit tests)
Verify output (trimmed, real):
```
test worked_example_scores_72 ... ok
test contribution_halves_after_600_seconds ... ok      (40 -> 20 -> 10)
test allowlist_needs_a_trusted_executable ... ok       (trusted ssh suppressed; same path user-writable flagged)
test repeats_update_one_finding ... ok
test no_finding_without_evidence ... ok
test alerts_fire_once_per_band ... ok
test findings_are_capped ... ok
test tree_score_includes_descendants ... ok
test explanation_matches_golden_text ... ok           (fixtures/explain/r001.txt)
test result: ok. 9 passed; 0 failed; 0 ignored
config: defaults_load, override_replaces_values, bad_files_are_rejected_with_clear_errors ... ok
```
Rendered golden (fixtures/explain/r001.txt) begins: `[HIGH 72] /tmp/x (pid 4312, started 12:00:01, parent /usr/bin/bash pid 4100, uid 1000)`.
`make lint` and `make test` green.
Result: PASS

### 2026-11-13 09:00 WP16 Rules R001-R004, R012
Did: core rules/files.rs (R001 credential read with system/untrusted confidence, R002 temp/world-writable exec, R003 fileless, R004 write or rename-into persistence with strong subjects, R012 decoy inode), rules/mod.rs ("~/" expansion per process home, fallback /home/*, /root), engine.rs (state + detector + decoy set; one code path for daemon and replay), replay_engine. scripts/gen_rule_fixtures.py writes 8 cases per rule (3 pos, 3 neg, 2 boundary) with hand-computed expectations; tests/rule_fixtures.rs replays them all. Mutation check: changing one expected score (87 -> 86) makes the test fail. Simulators testkit/sim/{cred_read,tmp_exec,memfd_exec,persist_write}.py with the `.sysscope-sim-ok` guard (refuse without it, run with it - checked on the host as the user).
Verify command: `cargo test -p sysscope-core --test rule_fixtures`
Verify output (trimmed, real):
```
test result: ok. 1 passed; 0 failed; 0 ignored    (40 fixtures, 5 rules x 3/3/2)
--- mutation check ---
1 failing: .../fixtures/rules/R012/boundary-also-credential: score of 500: got 87, want 86
```
`make lint` and `make test` green.
Result: PASS for fixtures. Simulator end-to-end (expected finding with evidence ids from the live daemon) BLOCKED(E1): needs WP12 daemon and root.

### 2026-11-13 09:40 WP05 Ground-truth workload + harness (verify)
Did: debian12 VM run of the itest binary (built on the host, shipped by `make itest-bin`). First run: 3/5 pass; two tests wrongly assumed wl's own exec happens before tracing (it is observed, correctly). Tightened the assertions (wl has exactly one exec of its own; children never exec / exactly one fileless exec) - stronger, not weaker. Leader-exits-first case confirms the WP04 EXIT signal: exactly one EXIT, emitted by the surviving non-leader thread.
Verify command: `make itest-bin && vm/run.sh debian12 "$(cat vm/tests/wp05_itest.sh)"`
Verify output (trimmed, real):
```
== sysscope-itest-lifecycle
/opt/sysscope/bin/sysscope-itest-lifecycle: /lib/x86_64-linux-gnu/libc.so.6: weak version `GLIBC_2.39' not found (required by ...)   <- weak symbol warning only; the binary runs
test exec_100_children_exactly ... ok
test fork_100_without_exec ... ok
test leader_exiting_first_gives_one_exit_from_the_last_thread ... ok
test memfd_exec_is_fileless ... ok
test threads_are_not_processes ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; finished in 8.27s
dmesg: no new bpf/BUG/WARNING/RCU lines
```
Result: PASS on debian12. Host `make test-root`: BLOCKED(E1).

### 2026-11-13 09:50 WP17 Rules R005-R008
Did: core rules/windows.rs: R005 (rename-after-write or unlink-after-new-sibling, common-extension share, truncate-existing across dirs; user-data roots minus excluded components; event time), R006 (per (exe, addr, port), BEACON_POINTS timestamps, CV of intervals, public-address confidence, max_keys LRU via an index), R007 (incremental distinct-destination counts), R008 (BudgetDrops input, consecutive seconds, evidence = latest event). Finding evidence ids capped (MAX_EVIDENCE_IDS). 36 more fixtures incl. boundaries 19/20 files, 12 s vs 10 s window, CV 0.14/0.16, 5/6 connects, 24/25 ports, 2/3 seconds. Cap tests: R006 keys = max_keys, R005/R007 windows = WINDOW_ENTRIES. Simulators ransom_sim.py, beacon.py, portscan.py (marker-guarded, own dir / loopback only). Performance: first version re-scanned windows per event (cap test 144 s in debug); now incremental (1.0 s).
Verify command: `cargo test -p sysscope-core` (rule_fixtures, windows, detect)
Verify output (trimmed, real):
```
test result: ok. 10 passed; 0 failed   (detect.rs incl. evidence_ids_per_finding_are_capped)
test result: ok. 1 passed; 0 failed    (rule_fixtures: 76 fixtures, 9 rules, each >= 3 pos / 3 neg / 2 boundary)
test result: ok. 2 passed; 0 failed; finished in 1.00s   (windows.rs caps)
```
`make lint` and `make test` green.
Result: PASS for fixtures and caps; simulator end-to-end BLOCKED(E1) (needs the live daemon).

### 2026-11-13 10:30 WP06 File events / WP07 Network events / WP08 Syscall stats (counts)
Did: WP06: fentry/security_file_open (bpf_d_path, leaf + PATH_TRUNCATED fallback, kthreads skipped), fentry/security_inode_rename and _unlink (bounded dentry walks), daemon decode, mount-table prefix, f_mode/f_flags -> read/write/create/trunc, kernel dev_t -> st_dev; wl gained open-relative, open-symlink, uring-open (raw io_uring syscalls). WP07: fentry/security_socket_connect (raw sockaddr), fentry/security_socket_listen (bound addr from the sock), daemon sockaddr parser (inet, inet6, v4-mapped -> inet, unix path / @abstract escaped, garbage -> other). WP08: raw_tp/sys_enter per-CPU LRU counts per (tgid, nr) behind the cheap gate and a cfg flag (`--syscalls count|off`), sys_exit latency in follow mode only, syscall names generated at build time from unistd_64.h, dump prints final `sysstat` lines. Bug found and fixed in the VM: on_connect rejected by the verifier ("R2 unbounded memory access") on 6.1 and 5.15.
Prototype check inside the guests (bpftool on the guest BTF): 6.1.0-54 and 5.15.0-203 have the same argument lists as the host 6.19 for security_file_open(file), security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags), security_inode_unlink(dir, dentry), security_socket_connect(sock, address, addrlen), security_socket_listen(sock, backlog).
Verify command: `make itest-bin && vm/run.sh debian12 "$(cat vm/tests/wp05_itest.sh)"`, same for ubuntu2204
Verify output (trimmed, real):
```
== debian12 (6.1.0-54-amd64)
== sysscope-itest-files       test result: ok. 5 passed; 0 failed   (1000 reads, 500 writes, 200 renames, 200 unlinks exact; (dev,ino)==lstat; paths; longpath -> PATH_TRUNCATED + "leaf-file"; badname bytes round-trip; relative + symlink resolved; io_uring open observed)
== sysscope-itest-lifecycle   test result: ok. 5 passed; 0 failed
== sysscope-itest-network     test result: ok. 1 passed; 0 failed   (300 v4 + 300 v6 connects, 50 refused, 1 udp, 13 listens exact)
== sysscope-itest-syscalls    test result: ok. 1 passed; 0 failed   (getppid count == 100000 exactly)
dmesg: no new bpf/BUG/WARNING/RCU lines
== ubuntu2204 (5.15.0-203-generic): files 5/5, lifecycle 5/5, network 1/1, syscalls 1/1 ok; dmesg clean
```
Result: WP06 PASS (debian12 + ubuntu2204), WP07 PASS (debian12 + ubuntu2204), WP08 count part PASS; WP08 followed-latency check pending (needs WP09 follow). Host for all: BLOCKED(E1).

### 2026-11-13 10:55 WP09 Follow mode + budgets (and WP08 latency)
Did: kernel follow inheritance at fork keyed on the parent's tgid (before any gate), followed entry removed when the process is gone; per-tgid token bucket (rate/burst from cfg, elapsed capped before multiplying, fractional tokens carried, compare-and-swap so tokens never go negative, lost updates allowed) for every event-emitting program; per-tgid budget and ring-buffer drop counters. Daemon: follow::start (insert root, scan /proc for descendants until two scans add nothing, then cfg.mode = follow), `--follow PID`, `--budget RATE/BURST`, final `budget` lines. wl gained --wait-stdin, gen3 (3 generations, last one a setsid double-fork daemon), sleep, nanosleep. My first tiny-ring test wrongly required the neighbour to lose nothing with a shared 64 KiB ring; the plan requires that only for the normal ring (b) and only the identity for (c) - the test now checks for (c) that every neighbour loss is counted.
Verify command: `make itest-bin && vm/run.sh debian12 "$(cat vm/tests/wp05_itest.sh)"`, same for ubuntu2204
Verify output (trimmed, real):
```
== debian12: sysscope-itest-follow   test result: ok. 4 passed; 0 failed
   follow_covers_three_generations_and_ignores_others        (all recorded events in the followed tree; unrelated wl: 0 events; gen-1..3 opened by 3 distinct descendants incl. the double-forked daemon)
   flood_loss_identity_holds_and_neighbour_loses_nothing      (received + budget_dropped + ringbuf_dropped == 200000; neighbour 1000/1000, drops (0,0))
   loss_identity_holds_with_a_tiny_ring_buffer                (same identity with --ringbuf-bytes 65536; neighbour losses all counted)
   followed_nanosleep_latency_is_measured                     (200 samples, mean within 1.0-3.0 ms)
   files 5/5, lifecycle 5/5, network 1/1, syscalls 1/1; dmesg: no new bpf/BUG/WARNING/RCU lines
== ubuntu2204 (5.15): follow 4/4, files 5/5, lifecycle 5/5, network 1/1, syscalls 1/1; dmesg clean
```
Result: PASS on debian12 and ubuntu2204 (WP08 latency part included). Host: BLOCKED(E1).

### 2026-11-13 11:15 WP10 /proc sampler + identity
Did: crates/sysscoped/src/sampler.rs with the procfs crate (stat: ppid, comm, flags->kthread, utime+stime, num_threads, starttime; statm resident x page size; io rchar/wchar; exe bytes; owner uid); vanished/unreadable processes skipped; CLOCK_BOOTTIME timestamps via rustix. Dump mode prints a full scan as a core `Samples` input about once per second. CPU % comes from the core (pure) from consecutive samples. wl gained spawn-hold, busy, alloc.
Verify command: `make itest-bin && vm/run.sh debian12 "$(cat vm/tests/wp05_itest.sh)"`, same for ubuntu2204
Verify output (trimmed, real):
```
== debian12: sysscope-itest-proc  test result: ok. 3 passed; 0 failed
   bpf_and_proc_keys_match_for_200_processes   (200 FORK child keys == 200 /proc keys, 200/200 equal)
   busy_loop_shows_about_one_core              (>= 2 samples in 90-110 %)
   allocation_shows_in_rss_within_ten_percent  (max RSS within 10 % of 200 MiB)
   files 5/5, follow 4/4, lifecycle 5/5, network 1/1, syscalls 1/1; dmesg: no new bpf/BUG/WARNING/RCU lines
== ubuntu2204: proc 3/3 and all others pass; dmesg clean
```
Result: PASS on debian12 and ubuntu2204. Host: BLOCKED(E1).

### 2026-11-13 12:10 WP12 Daemon assembly
Did: collector.rs (shared loader; poller T1 drains the ring buffer into a 65536 bounded channel with blocking send, applies follow/unfollow, 1 Hz loss/budget/syscall reads), sampler thread T2 (latest-wins channel 64), core thread T3 owning the Engine (events, samples, exe trust facts via /proc/<pid>/exe, passwd homes, 500 ms snapshots encoded once, 1 s ticks, Detail with /proc maps after a start-time check, Follow/Unfollow, Act and Glasshouse answered "not enabled/unavailable", --record JSONL of core inputs), server.rs (socket 0660 root:group in a 0750 dir with mode set before listen, stale-socket handling, SO_PEERCRED logged, 8 clients max, per-client snapshot slot / 4096 events / 256 alerts drop-oldest with counters, writer with 5 s timeout, reader with strict decode and Error-then-close), config files (/etc/sysscope/sysscoped.toml, rules.toml, allow.toml; bad file = refuse to start), SIGTERM/SIGINT shutdown removing the socket. Bugs found by the VM runs and fixed: poll interrupted by SIGTERM reported as failure; reply "Error then close" could be lost to a close race; duplicate EXIT from a racing thread (BPF exit_seen map).
Verify command: `make itest-bin && vm/run.sh debian12 "$(cat vm/tests/wp12_tools.sh)" && vm/run.sh debian12 "$(cat vm/tests/wp05_itest.sh)"` (twice), same on ubuntu2204; `vm/run.sh debian12 "$(cat vm/tests/wp12_rss.sh)"`
Verify output (trimmed, real):
```
== sysscope-itest-server   test result: ok. 6 passed; 0 failed; finished in 59.05s
   eight_clients_then_the_ninth_is_refused                  (9th gets Error too_many_clients; after one leaves a new one gets in)
   slow_client_is_cut_off_and_others_keep_their_snapshots   (other client's max snapshot gap < 700 ms; slow client reaches EOF)
   bad_frames_get_an_error_and_the_daemon_survives          (malformed, 2 MiB frame, unknown type, proto 99 -> Error + close; daemon still serves)
   detail_and_follow_work_over_the_socket                   (Detail with maps; Follow -> ActResult ok, snapshot mode follow, row followed)
   sigterm_removes_the_socket
   daemon_uses_only_unix_and_netlink_sockets                (strace -f -e trace=network for 30 s: only AF_UNIX/AF_NETLINK)
files 5/5, follow 4/4, lifecycle 5/5, network 1/1, proc 3/3, syscalls 1/1; dmesg: no new bpf/BUG/WARNING/RCU lines
(debian12 run 1 and run 2: all ok; ubuntu2204: all ok)
--- 10 minutes of wl churn ---
rounds=22649 daemon VmRSS=120508 kB VmHWM=120508 kB
WP12 RSS PASS
```
Result: PASS on debian12 and ubuntu2204. Host: BLOCKED(E1).

### 2026-11-13 12:45 WP13 CLI
Did: crates/sysscope-cli: conn.rs (socket discovery dev -> installed or --socket, Hello, errors mapped to exit codes 1/2/3/4/5 with the exact command to fix), out.rs (table, tree with tree scores, event lines, 5.6 explanations, JSON with C1/bidi escaped), export.rs (JSON/CSV, redaction on by default via sysscope_core::redact, --raw warns, --redact-ips, Exec argv redacted in evidence), main.rs (status, top, tree, tail [--proc] [--count|--seconds], follow, unfollow, detail [--maps], findings, export, replay FILE offline, glasshouse stub, --json everywhere). Core gained display.rs (C1 controls and bidi overrides -> \u{XXXX}, closing the WP02 gap) and redact.rs (homes, other homes -> ~userN, user/host placeholders, secret flags and KEY=VALUE, URL userinfo, IP pseudonyms). wl gained open-path and "--".
Verify command: `make itest-bin && vm/run.sh debian12 "$(cat vm/tests/wp05_itest.sh)"` (plus unit tests on the host)
Verify output (trimmed, real):
```
== sysscope-itest-cli   test result: ok. 5 passed; 0 failed; finished in 24.97s
   exit_code_3_when_no_daemon_runs                    (status -> 3 "not running"; unknown command -> 2)
   status_top_tree_and_json
   hostile_file_names_are_escaped_in_output           (tail output: no ESC / control bytes; shows \x1B[31mred)
   export_is_redacted_by_default_and_csv_parses       (R001 + R002 live; no "hunter2", "bob:pw", "/root/.ssh" in default export; --raw has them + warning; CSV parsed by python csv; findings text has "Why it is flagged:" and "To silence:")
   replay_of_a_recording_finds_the_same_rules         (daemon --record, then `sysscope replay` shows R001 and R002)
cli 5/5, files 5/5, follow 4/4, lifecycle 5/5, network 1/1, proc 3/3, server 6/6, syscalls 1/1; dmesg clean
```
Result: PASS

### 2026-11-13 13:15 WP19 GUI model + transport
Did: crates/sysscope-gui is now lib + thin bin. model.rs: pure view-model (connection state incl. daemon-down / permission / proto mismatch / replay, displayed snapshot, pause keeping only the newest snapshot and counting skipped ones, sort column + direction with key tie-break, case-insensitive filter over exe/pid/uid/rule, selection by key or pid with Detail requests, tabs, bounded detail cache (16) and alert list (256, newest first, click selects + opens Findings), tree with missing parents as roots and loop protection, multi-user detection for the 9.1 notice, all text escaped with core display::safe). net.rs: live reader thread (Hello, Subscribe, forward to a bounded channel, request writer thread, reconnect with 0.5-5 s backoff) and replay of *.frames.jsonl (recorded / fixed / max pace, garbage lines skipped, frame size cap).
Verify command: `cargo test -p sysscope-gui`
Verify output (trimmed, real):
```
running 9 tests
model: sort_is_stable_and_toggles, filter_matches_exe_pid_uid_and_rule_case_insensitively, pause_freezes_display_but_keeps_only_the_latest,
       selection_survives_resort_and_clears_on_eviction, tree_nests_children_and_handles_missing_parents,
       alerts_are_bounded_newest_first_and_clickable, hostile_names_are_escaped_and_states_tracked ... ok
net:   live_reports_down_then_connects_and_reconnects (fake daemon socket), replay_skips_garbage_and_delivers_messages ... ok
test result: ok. 9 passed; 0 failed; 0 ignored
```
`make lint` green.
Result: PASS

### 2026-11-13 14:30 Gate review (fresh subagent) - partial fixes, session stopped by usage limit
Review findings (subagent, read-only): 1 O(n^3) tree score; 2 snapshot/Detail > 16 MiB silently skipped; 3 follow scans on poller unbounded + bare tgid; 4 follow switch/failure leaves kernel filtering; 5 alerts_dropped / decode_errors not surfaced; 6 BPF maps keyed by bare tgid (pid reuse), exe_facts no start check, budget delta after LRU eviction; 7 alerted map unbounded; 8 newline injection in CLI explanation; 9 maps read whole file / exe stat on core thread; 10 truncated walks lose PATH_TRUNCATED, mount table read once; 11 doc comment in bstr.rs overstates safety, idle clients hold slots.
FIXED with regression tests (host unit tests pass): 1 (tree_scores linear, test deep_fork_chain_annotates_quickly), 7 (Detector::prune, test alert_state_is_pruned_with_evicted_processes), 8 (explain::render_safe per line, test rendered_explanation_cannot_gain_lines_from_a_path).
FIXED in code, NOT YET VERIFIED in a VM: 3 (max 20 scans, root start-time check, descendants must start after root), 4 (follow clears old set; failure -> system-wide; busy -> Error reply), 6 (followed_tgid value carries start_ticks checked in gate/fork; budget, sys_count, sys_lat keyed with start time; budget delta handles LRU reset; last_budget pruned).
OPEN: 2, 5, 9, 10, 11; exe_facts start-time check (part of 6). GUI: WP20 kittest tests and the 6 screenshot descriptions still to record (screenshots generate and pass the colour check).

### 2026-11-13 15:30 M1/M2 gate slice: adversarial review fixed
Did: fixed every confirmed finding of the fresh-subagent review, each with a regression test:
1 tree score linear (deep_fork_chain_annotates_quickly; follow-mode tree in snapshot now BFS); 2 snapshots always fit (exited rows dropped, then names shortened, logged) and Detail shrunk to fit; CLI skips one failing Detail (hostile_snapshot_still_fits_in_a_frame, hostile_detail_is_shrunk_to_fit); 3 follow: at most 20 /proc rescans, root start-time check, descendants must start after root; 4 follow clears the old set, failure returns to system-wide, busy -> Error (follow_switch_and_stale_key itest); 5 dropped alerts reported as Error alerts_dropped, decode errors in Loss.decode (dropped_alerts_are_reported); 6 BPF maps keyed with start time, budget delta handles LRU reset, exe trust requires matching start time (own_process_facts_and_maps); 7 alert state pruned (alert_state_is_pruned_with_evicted_processes); 8 explanation rendered line by line (rendered_explanation_cannot_gain_lines_from_a_path); 9 /proc maps streamed with the 5000-line cap; 10 truncated walks shown as ".../..." without a mount prefix, mount table reloaded every 10 s (truncated_walk_is_marked_not_prefixed); 11 bstr doc comment corrected. Not changed (documented in UNVERIFIED.md): 8 idle clients can hold all slots (only sysscope-group members can connect); unknown client fields stay ignored (plan 4.5 requires forward compatibility).
Verify command: `make lint && make test`, then `make itest-bin && vm/run.sh debian12 ... wp00_tools.sh, wp05_itest.sh` (and ubuntu2204 before the last batch)
Verify output (trimmed, real):
```
make lint: clean; make test: all ok (sysscoped 22 unit tests)
== debian12: cli 5/5, files 5/5, follow 4/4, lifecycle 5/5, network 1/1, proc 3/3, server 7/7 (incl. follow_switch_and_stale_key), syscalls 1/1
dmesg: no new bpf/BUG/WARNING/RCU lines   RC=0
== ubuntu2204 (ProcKey-keyed maps): all 30 ok, dmesg clean
```
Result: PASS for the gate slice. Full gate (host test-root, bench) still BLOCKED(E1).

### 2026-11-13 16:20 WP20 GUI views
Did: eframe 0.37 / egui 0.37 (glow) window: ui.rs (top bar with status, mode badge, search, pause, export, loss indicator, multi-user notice; table/tree with sortable headers and score shown as number + word + colour; detail tabs overview charts (egui_plot), files, network, syscalls, children, memory maps, findings in the 5.6 text; alerts list; Glasshouse section with the verbatim 6.4 text; states daemon-down / permission / protocol mismatch / connecting with the exact commands), app.rs (pumps the reader, actions -> requests, redacted export to $HOME with a review reminder, screenshot after N frames then exit), main.rs (refuses euid 0; --replay, --pace, --screenshot, --after-frames, --select, --tab, --socket, --paused). `sysscope replay FILE --frames OUT` builds a GUI replay from any events recording; scripts/gen_gui_fixture.py makes the deterministic demo recording; `make gui-shot` (scripts/gui-shots.sh + png_colours.py, stdlib PNG decoder). Accessibility labels set with widget_info. Two fixes found by looking at the PNGs: glyphs missing from the default font (now words), and a flat daemon-down page (now a highlighted warning box).
Verify command: `cargo test -p sysscope-gui --test ui` and `make gui-shot`, then each PNG opened and inspected
Verify output (trimmed, real):
```
test every_required_element_has_its_label ... ok        (status, mode, search, pause, export, loss, procs, alerts, detail-<7 tabs>)
test search_sort_pause_tab_and_alert_click_change_the_model ... ok
test glasshouse_limits_text_is_in_the_window ... ok
test result: ok. 3 passed; 0 failed
target/shots/system-wide.png 1400x900 961 colours OK
target/shots/detail-files.png 1400x900 1221 colours OK
target/shots/detail-findings.png 1400x900 1355 colours OK
target/shots/following.png 1400x900 2227 colours OK
target/shots/daemon-down.png 1400x900 1178 colours OK
target/shots/paused.png 1400x900 976 colours OK
```
Screenshot descriptions (opened and read):
- system-wide: top bar "replay of fixtures/gui/demo.frames.jsonl", badge "System-wide", search box, Pause, Export, red "LOST EVENTS: ring buffer 12, budget 340, scratch 0", "Monitoring all users on this machine"; table of 34 processes sorted by CPU% (rustc 95 %), kernel threads as [kthreadd] etc., /tmp/.cache-x/update-helper with "89 high" in red, ancestors with "tree 89"; right pane "Select a process" and a collapsed Glasshouse section; alerts list with R001 and R002.
- detail-files: firefox (pid 1100) selected and highlighted, Files tab active, cache2 entry paths with open counts and r/rw.
- detail-findings: update-helper selected, Findings tab shows three full explanations ([HIGH 89] header, rule line with ATT&CK, What happened, Why it is flagged, Could be harmless if, Evidence ids, To silence line) - all legible.
- following: badge "Following /usr/bin/bash (1030)", followed row marked "*", "Stop following" button, Overview tab with CPU % and memory charts.
- daemon-down: red status "daemon not running", badge "Not connected", Pause/Export disabled, orange-framed warning with the socket error, "sudo systemctl start sysscoped" and the dev command, "reconnects by itself", product statement.
- paused: "Resume" button, orange "PAUSED (25 updates skipped)", table frozen at the first snapshot (33 processes), alerts still listed.
Result: PASS

### 2026-11-13 17:40 WP21 Follow UX, loss, robustness
Did: follow from the detail button and a right-click row menu, both through a confirmation window ("Other processes will not be traced while following."); red loss banner with totals per reason and Dismiss (comes back when more is lost); amber "showing the last data received" banner while disconnected; UI wakes on data (reader thread requests a repaint) with a 1 s heartbeat instead of 10 fps polling; display rows cached and rebuilt only on data/view change; exe column takes the remaining width, others fixed (auto-sizing measured all 2000 rows on first layout); protocol decode parses messages once (tag-only first pass instead of a JSON tree), which also helps the daemon and CLI; dependencies built with opt-level 2 in dev/test profiles. --shot-at for timed screenshots; scripts/fake_daemon.py (Unix socket only) and scripts/gui-restart.sh; scripts/gui-stress.sh.
Verify commands: `cargo test -p sysscope-gui` (incl. tests/stress.rs), `scripts/gui-stress.sh`, `scripts/gui-restart.sh` + inspecting the PNGs
Verify output (trimmed, real):
```
model: follow_needs_confirmation_and_loss_banner_reappears_on_new_loss ... ok   (10 model/net unit tests ok)
stress: no_frame_over_50ms_with_2000_processes ... ok   (40 snapshots of 2000 rows, table and tree mode; worst frame 12.4 ms after the fixes, was 51.5 ms)
gui-stress: 2000 processes at 2 Hz over 30 s: whole process 32.0-35.2% of one core (incl. software rendering), GUI threads 6.2-7.0%, VmHWM ~128000 kB  -> PASS
restart-1-connected.png 692 colours OK / restart-2-down.png 860 colours OK / restart-3-recovered.png 692 colours OK
```
Screenshots: restart-2-down shows red "daemon not running", badge "Not connected", Pause/Export greyed, last table kept (now with the amber stale-data banner); restart-3-recovered shows green "daemon 0.0.1 on 6.19.14+kali-amd64 (fixture)", "System-wide", controls enabled, live table. system-wide now shows all ten columns incl. score with the loss banner.
Result: PASS (CPU on GUI threads; see Deviations)

### 2026-11-13 18:10 WP22 Decoys + manifest
Did: crates/sysscope-glasshouse/src/decoys.rs: per-run fake decoys exactly as listed in plan 6.2 (SSH key pair from ssh-keygen with comment victim@glasshouse - a fake PEM in seeded mode -, known_hosts, AWS documented example credentials, Chrome Login Data, Firefox logins.json + key4.db, .bash_history, passwords.txt, wallet.dat, GnuPG key, 20 Documents with real magic headers, 10 JPEGs, decoy /etc/shadow with fake hashes), manifest (path, sandbox path, dev, ino, size, sha256, entropy, mode) written 0600 as manifest.json; SplitMix64 generator for reproducible tests; no file copied from the host.
Verify command: `cargo test -p sysscope-glasshouse`
Verify output (trimmed, real):
```
test decoys::tests::entropy_bounds ... ok
test decoys::tests::b64_matches_known_values ... ok
test decoys::tests::manifest_matches_files_on_disk ... ok        (re-hash, (dev,ino), size, entropy, mode for all 42)
test decoys::tests::same_seed_same_content_other_seed_differs ... ok
test decoys::tests::no_decoy_contains_host_data ... ok          (real ssh-keygen run; no $USER, hostname or $HOME bytes in any of the 42 files)
test decoys::manifest_tests::manifest_round_trips_through_json ... ok
test result: ok. 6 passed; 0 failed
```
Correction: the first WP22 commit was pushed while manifest_round_trips_through_json failed (one entropy value lost its last digit through JSON). Fixed by enabling serde_json's float_roundtrip feature; the output above is from after the fix (3 consecutive runs green, make lint and make test green).
Result: PASS

### 2026-11-13 19:15 WP23 Launcher
Did: sysscope-glasshouse binary: `prepare` (decoys + manifest, synthetic /etc with copies of ld.so.cache, ld.so.conf(.d), alternatives, ssl/certs, nsswitch.conf, localtime and generated passwd/group/hostname/hosts/resolv.conf, three seccomp filter files, home owned by sysscope-box, run dir 0750 root:sysscope-box), `stage2` (as sysscope-box in the transient unit: waits on the FIFO, execs /usr/bin/bwrap with the 6.2 arguments and --add-seccomp-fd x3; systemd starts it with only fds 0-2 so no close_range is needed), `run-local` (root: 512 MiB nodev,nosuid tmpfs run dir, prepare, systemd-run --wait with every 6.2 property - a rejected property makes the unit fail and the run refuse -, cgroup id = inode of the unit cgroup dir, FIFO release, output printed escaped, unmount + remove), `availability` (real bwrap start as sysscope-box via setpriv; reason includes the AppArmor/userns sysctl, which is never changed). seccomp.rs: seccompiler filters (EPERM list incl. clone with CLONE_NEW* and personality, clone3 -> ENOSYS) plus a hand-built x32 kill filter (seccompiler only checks AUDIT_ARCH, which x32 shares). packaging/sysusers/sysscope.conf.
Verify command: `make release && vm/run.sh debian12 "$(cat vm/tests/wp00_tools.sh)"` then `wp23_availability.sh` and `wp23_glasshouse.sh` in debian12 and ubuntu2404
Verify output (trimmed, real):
```
== debian12 (bubblewrap 0.8.0, systemd 252)
available
availability rc=0 run-local rc=0 leftover_run_dirs=0   WP23 AVAILABLE PASS
glasshouse: unit sysscope-gh-832-1794544521 cgroup /sys/fs/cgroup/system.slice/sysscope-gh-832-1794544521.service id 2828
OK uid 1000 / OK only the specified tree (bin dev etc home lib lib64 proc run sample sbin tmp usr var) / OK synthetic passwd / OK loopback only / OK no other interfaces
OK NoNewPrivs 1 / OK Seccomp 2 / OK CapEff, CapPrm, CapBnd, CapInh, CapAmb zero / OK decoys in home / OK no /sys / OK only box processes (3) / OK fds 0-2 only
run-local rc=0   WP23 GLASSHOUSE PASS
== ubuntu2404 (bubblewrap 0.9.0)
unavailable: bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted (kernel.apparmor_restrict_unprivileged_userns = 1: this system's AppArmor policy blocks unprivileged user namespaces; SysScope does not change that setting)
availability rc=4 run-local rc=4 leftover_run_dirs=0   WP23 UNAVAILABLE-CORRECTLY PASS
```
Unit tests: seccomp namespaces_refused_and_clone3_falls_back, ordinary_syscalls_still_work, programs_serialize_to_eight_bytes_per_instruction ok.
Bugs found on the way: the probe first lacked the /lib64 symlink (false "unavailable" on Debian) and my VM script accepted that; both fixed (script now derives the expected outcome from the sysctls).
Result: PASS in VMs; host run BLOCKED(E1).

### 2026-11-13 20:40 M3 gate review fixes (GUI/CLI)
Did: fixed every finding of the fresh-subagent M3 review.
- Core: explanation fields escape CR/LF, so a hostile name cannot forge extra explanation lines. `dangerous()` also covers zero-width, line/paragraph separators, BOM and tag characters. Redaction gained more secret flags (--api-key, --auth-token, -u, ...), `-psecret`, Authorization/Cookie header args, whole-word user/host replacement, and IP pseudonyms inside free text.
- Proto: `read_line_bounded`, used for GUI and CLI replay. Decode errors never echo control bytes. `Loss.decode` counts undecodable kernel events.
- GUI: the reconnect writer thread is joined per session, so there is no leaked writer. Loss sums saturate. Syscall/perm/rule text is escaped. Detail lists are capped. A full request queue is reported to the user, not dropped silently. Exports use `create_new`.
- CLI: exported finding text (title, subject, why, summary) is redacted. CSV cells are escaped and protected against formulas (`'` prefix on = + - @). Daemon error text is escaped. `tail` waits with poll() instead of read timeouts. `recv_until` is bounded (100 000 messages). `tree` is linear. `status` shows undecodable events. `tail --json` emits `{"client_dropped":n}`. `replay` uses bounded lines and counts the lines it skipped.
Verify command: `make lint && make test && make itest-bin && /tmp/claude-1000/wait-vm-run.sh debian12 vm/tests/wp00_tools.sh vm/tests/wp05_itest.sh`
Verify output (trimmed, real):
```
make lint: Finished `dev` profile ... (fmt --check, clippy -D warnings clean)
make test: every "test result: ok." (core 22, proto, cli 3 incl. csv_cells_are_safe_and_formula_proof and daemon_error_text_is_escaped, gui kittest + stress, glasshouse)
debian12: cli 5, files 5, follow 4, lifecycle 5, network 1, proc 3, server 7 (incl. follow_switch_and_stale_key), syscalls 1 -> all ok; RC=0
```
(The GLIBC_2.39 weak-version line before each itest binary is the known loader warning recorded above; the binaries run.)
Result: PASS (M3 gate slice). The full gate (`make test-root` on the host) and the v0.1.0 tag stay BLOCKED(E1) on Q1.

### 2026-11-13 22:30 WP24 Trace integration, differ, report, UI
Did:
- **Daemon (`glasshouse.rs`).** Uploads are streamed to `/var/lib/sysscope/glasshouse/<id>.sample` (0600; strict base64, chunks in order, declared size enforced). The sample name is sanitised. Name, args and timeout go in a job file. The helper is started as `systemd-run --wait --pipe sysscope-glasshouse run <id>`, and its stdout is parsed strictly (16 MiB line cap, deny_unknown_fields). On the helper's Need, the daemon:
  - records the box root ProcKey from /proc;
  - sets the decoy set for R012;
  - has the poller put the cgroup into `followed_cgroup` and rewrite run-dir rename/unlink paths to what the sample sees (`/home/victim/...`, `/etc/...`), and only then answers Go.
  - Events from the box tree are attributed through Fork lineage. They fill the timeline (cap 20 000) and live decoy states (pushed at most every 300 ms). `~` is the sandbox home for box processes.
  - The report merges trace reads into the differ's states and adds connections, processes, findings of box processes, loss during the run, notes and the 6.4 text. It is sent to the client and saved 0640 root:sysscope in `/var/lib/sysscope/reports`.
  - The Welcome feature `glasshouse` is offered only if the helper's real probe succeeds.
- **Helper.** `run` (daemon-driven), `diff` (as sysscope-box, refuses root), `run-local [--calibrate]`, and stage2 reading `job.json`. The kill is `systemctl kill SIGKILL` at the timeout or on cancel. The differ runs only after the box cgroup is gone.
- **Differ (`differ.rs`).** Per-component O_NOFOLLOW, lstat only, regular files opened with NONBLOCK and inode re-check. Caps: 20 000 entries, 64 MiB per file, 30 s, depth 64. States are renamed (same inode), modified (hash), deleted (missing inode, only if the walk completed) and created (inode not in manifest or baseline). Other types are listed but never opened.
- **Core.** `ghreport` (text report, entropy sentence, counts) and `GLASSHOUSE_LIMITATION`, checked verbatim against MASTER_PLAN.md by a test.
- **Proto.** `helper` line protocol, strict `b64`, and additive fields (GhStatus.decoys, CreatedFile.kind, GhReport.notes).
- **CLI.** `sysscope glasshouse run [--timeout S] FILE [ARGS]`: prints the 6.4 text, uploads bytes, shows progress, then the report as text or `--json`.
- **GUI Glasshouse page.** 6.4 text always on top, in-window file picker, args, timeout, run/cancel, live decoy grid (word and colour), report with before/after table, connections, findings, notes, timeline and export (txt + json, create_new). New flag `--page glasshouse`.
- **Demo and tests.** `testkit/sim/fake_malware.py` refuses to run unless HOME=/home/victim and hostname=glasshouse. Also added: `vm/embed.sh`, `vm/tests/wp24_glasshouse.sh`, the fixtures `fixtures/gui/glasshouse.report.json` (real VM report) and `glasshouse.frames.jsonl` (`scripts/gen_gh_fixture.py`), and the `glasshouse-report` state in `make gui-shot`.
Verify command: `make lint && make test && make release`, then for each of debian12 and ubuntu2204: `vm/run.sh <d> "$(vm/embed.sh testkit/sim/fake_malware.py:/tmp/fake_malware.py)
$(cat vm/tests/wp24_glasshouse.sh)"`; the same on ubuntu2404; `bash scripts/gui-shots.sh`
Verify output (trimmed, real):
```
== debian12 (kernel 6.1, systemd 252, bubblewrap 0.8.0)
OK   daemon offers glasshouse
read: ['/home/victim/.aws/credentials', '/home/victim/.ssh/id_ed25519']
modified+renamed: 20 entropy rose: 20 e.g. 4.17 -> 7.94
deleted: 10 created: [('/home/victim/README_RESTORE.txt', 'file')]
connections: [('203.0.113.10', 443, 1)]
findings: ['R001', 'R004', 'R005', 'R012']
loss: {'ringbuf': 0, 'budget': 0, 'scratch': 0, 'decode': 0, ...} notes: ['pre-existing non-decoy file changed: /home/victim/.bashrc'] exit: 0 timed_out: False
OPENS_FROM_BWRAP 120 timeline 162 processes 3
REPORT PASS
decoys: 2 read, 20 modified, 20 renamed, 10 deleted (of 42); 1 new file(s); 1 connection attempt(s)
  /home/victim/Documents/file00.docx  [modified, renamed]
      now named /home/victim/Documents/file00.docx.locked
      size 1889 -> 1889 bytes, entropy 4.2 -> 7.9 bits/byte
      entropy rose from 4.2 to 7.9 bits/byte, consistent with encryption or compression
== 2. calibration (strace -f, successful opens only, seccomp off, run-local)
successful opens under strace: 134, of which O_PATH (no data access, never reach security_file_open): 14, data opens: 120
daemon trace opens from bwrap on: 120 (budget+ringbuf drops 0)
OK   every data open of the box is attributed
== 3. demo run while following an unrelated process
following pid 1283 (1 processes)
OPENS_FROM_BWRAP 120 timeline 162 processes 3
REPORT PASS
leftover entries in /var/lib/sysscope/glasshouse: 0
      3 -rw-r----- root sysscope        (one saved report per run)
WP24 GLASSHOUSE PASS
== ubuntu2204 (kernel 5.15): same counts and findings; strace 151 successful opens, 14 O_PATH, 137 data opens = 137 traced; REPORT PASS x2; WP24 GLASSHOUSE PASS
== ubuntu2404: unavailable: bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted (kernel.apparmor_restrict_unprivileged_userns = 1 ...)
   sysscope: Glasshouse is not available on this system (the daemon does not offer it; ...)   WP24 UNAVAILABLE-CORRECTLY PASS
make lint: clean; make test: all ok (glasshouse 12 incl. differ x3, core incl. ghreport x2, proto incl. b64 x2 + helper, cli 4, gui 11 lib + ui 4 incl. glasshouse_page_shows_the_report, sysscoped incl. mounts glasshouse rewrite)
gui-shots: target/shots/glasshouse-report.png 1400x900 1620 colours OK (and the 6 WP20 states OK)
```
Screenshot (glasshouse-report.png, opened and checked):
- Top bar: "Processes | Glasshouse" (Glasshouse selected).
- The full 6.4 text in white on an amber band.
- Form: Program file with Browse..., Arguments, Timeout 60. "Run in Glasshouse" is disabled (replay, no daemon). Status line: "run 1794547283-1: finished. report saved to /var/lib/sysscope/reports/1794547283-1.json".
- "Decoys: 32 of 42 touched", then 42 tiles, 7 per row, each with the file name and the state as a word:
  - id_ed25519 and credentials: "read" (amber);
  - file00-19: "modified, renamed" (orange);
  - photo00-09: "deleted" (red);
  - the rest "untouched" (green).
- "Report: fake_malware.py (exited with code 0)" and "2 decoys read, 20 modified, 20 renamed, 10 deleted; 1 new file(s); 1 connection attempt(s); 6 finding(s)".
- A striped Before/after table: Decoy (old -> new name), What happened, Size before -> after, Entropy before -> after. Each document row shows 4.2 -> 7.9 "(consistent with encryption or compression)".
All text is legible.
Bugs found on the way:
- Rename/unlink paths came out as `/home/Documents/...`, because the run tmpfs was not in the mount table. Fixed with per-run path rewrites set before Go.
- The box user's host home "/" broke the `~/` classes. Fixed: box processes get /home/victim.
- A second run right after the first got "busy". Fixed: the run slot is freed once the report is sent.
- My first calibration miscounted strace's table and included O_PATH opens. Replaced by a per-open strace log.
- `vm/embed.sh` output lost its last newline in `$(...)`.
- I had run some unit tests with Debian's cargo 1.94 instead of the pinned 1.100. All results above are from `make` (pinned toolchain).
Result: PASS in VMs (debian12, ubuntu2204; ubuntu2404 correctly unavailable). Host run BLOCKED(E1) on Q1.

### 2026-11-13 23:40 WP25 Adversarial suite
Did:
- **Probes.** `testkit/hostile/hostile.py` has one probe per row of plan 6.5, 20 in total: syscalls (39 refused, x32 and i386 killed), hostfiles, procs, network, sockets (including an abstract socket and an X11 socket listening outside the box), setuid, userns, tiocsti, forkbomb, membomb, cpuhog, diskfill, flood, tamper, coredump, torture (symlinks, FIFO, device names, ANSI/RTL/newline/non-UTF-8 names, a ~10 000-character path, 1 GiB sparse attempt, 100 000 files), persist, fds, detect, sidechannel.
- **Guards.** Each probe writes ~/VERDICT.txt, which comes back through the report. In-box guard: hostname, HOME, uid 1000 and the hypervisor flag. `run_all.sh` guard: /etc/sysscope-test-vm and DMI=QEMU. Both refuse on the host (checked, exit 3).
- **Runner checks.** Leftover processes, units and mounts after every probe; host disk; the core handler (a piped core_pattern installed in the VM only, then restored); flood loss and R008; torture timing, plus no raw control bytes in the JSON or the text report (new `sysscope glasshouse report FILE`).
- **Driver.** `vm/hostile.sh` times SSH while the suite runs. `make vm-hostile` covers debian12, ubuntu2204 and ubuntu2404.
Fixes from ESCAPED results:
- (1) coredump ESCAPED: the host root core handler ran 3 times under LimitCORE=0. Fixed with LimitCORE=1, now CONTAINED with 0 handler runs.
- (2) Reports said "exited with code 1" for an OOM kill, because that was systemd-run's own code. The helper now parses systemd-run's closing lines: exit code only for real exits, otherwise a note such as "stopped by the 1 GiB memory limit (oom-kill)". Unit test added.
- (3) The diskfill LimitFSIZE check ran on a full filesystem and proved nothing. It now frees the space and truncates a sparse 300 MiB file.
- (4) Two driver bugs of mine: `set -e` from lib.sh, and a remote check whose status was misread as a failed SSH.
Verify command: `make release && vm/hostile.sh debian12; vm/hostile.sh ubuntu2204; vm/hostile.sh ubuntu2404` (the same as `make vm-hostile`). WP24 VM check re-run after the fixes.
Verify output (trimmed, real):
```
debian12: PROBE syscalls..sidechannel: all CONTAINED; forkbomb/cpuhog ended: timeout; membomb ended: exit None ['the sample was stopped by the 1 GiB memory limit (oom-kill)']
  diskfill host / free 9799 -> 9799 MiB; flood budget drops counted 3716728, R008 True; coredump handler invocations 0
  torture took 2s; notes: differ stopped at 20000 entries ...; 1 file(s) larger than 64 MiB were hashed only in part
  HOSTILE SUMMARY: 20 contained, 0 escaped; slowest SSH per phase 139-200 ms (forkbomb 178 ms)   VM-HOSTILE debian12 PASS
ubuntu2204: HOSTILE SUMMARY: 20 contained, 0 escaped; forkbomb 197 ms, torture 312 ms   VM-HOSTILE ubuntu2204 PASS
ubuntu2404: HOSTILE UNAVAILABLE-CORRECTLY PASS   VM-HOSTILE ubuntu2404 PASS
WP24 re-run debian12: REPORT PASS x2, "ran 0.2 s, exited with code 0", 120 data opens = 120 traced   WP24 GLASSHOUSE PASS
```
Honest gap: the memory bomb is OOM-killed in under 1 s, so the 2 s SSH sampling never landed inside it. The membomb responsiveness bar is not directly measured; the fork bomb's is (178/197 ms).
Result: PASS (VMs). The Gate M4 adversarial review is running; its findings are still to be fixed.

### 2026-11-14 01:30 Gate M4 (Glasshouse) - adversarial review and fixes
Did: a fresh subagent reviewed Glasshouse as an attacker (read-only). Every finding was checked against the code and handled:
1. HIGH, fixed. A sample could hang the helper for good: the differ's output was unbounded and was read before `wait()`, so a full pipe deadlocked; there was also no daemon timeout. Now:
   - the differ walks re-opened directories by a name tree (no fd pile-up), keeps paths of at most 1 KiB, lists at most 1000 created entries plus a note, and keeps output under 4 MiB in a test with 3000 long non-UTF-8 names;
   - the helper drains the differ's output on a thread, with a 12 MiB cap and a 60 s kill;
   - the helper unit has MemoryMax=1G and RuntimeMaxSec=timeout+300;
   - a daemon watchdog kills both units after timeout+300 s and frees the slot.
2. HIGH, fixed. A Fork event dropped by the budget or a full ring buffer hid whole box processes. While the sample runs (from Go to the new helper `Ended` message, sent before the differ starts), the daemon adopts events from the sandbox uid whose /proc cgroup is the box unit. The report notes adopted processes and the budget drops of box processes. VM: the flood probe's child really lost its Fork event on debian12, was adopted, and its decoy read is in the report.
3. MEDIUM, fixed. The differ silently skipped directories it could not open or list. Every open, list or stat error now makes the walk incomplete, with a note. Directories and files the sample set to chmod 000 get owner access restored (noted). An unreadable decoy is "unknown", never "modified". Hard links to decoys are noted, not reported as renames.
4. MEDIUM, fixed. The list of box processes was unbounded (fork chains). It is capped at 10 000 (overflow noted), reports list 1000 children, `fit_report` also cuts children and findings, the saved copy is the fitted report, and reports are rotated (200).
5. MEDIUM/LOW, fixed. Every error path after systemd-run starts now kills the box unit and reaps systemd-run. umount falls back to `--lazy`. The daemon sweeps stale units, mounts and files at start. The runner's leftover check now includes helper units.
6. LOW, fixed. The FIFO is opened O_NONBLOCK (ENXIO if stage2 died) instead of blocking forever.
7. LOW, partly fixed. The 256 MiB `sync_all` on the core thread is removed, and a stalled upload is dropped after 60 s. Accepted: chunk writes (at most 64 KiB) and the report save stay on the core thread.
8. LOW, fixed. Saved reports and the GUI JSON export go through `display::json_safe` (moved to core: C1, bidi, zero-width and tag characters). The torture check now greps all outputs for C1/bidi bytes.
9. LOW, fixed. Box executables are never stat'ed on the host; they are untrusted.
10. LOW, fixed. The probes were too weak:
    - syscalls and tamper now require `Seccomp: 2` and 3 filters, and 15 more syscalls are tried (including clone with NEWNS, NEWNET and NEWPID);
    - torture adds 20 000 long non-UTF-8 names, a 64-deep chain of 255-byte names, chmod-000 directories and decoys, and a hard link;
    - flood adds the fork-after-flood attribution check.
11. Half wrong. The CLI already stops on a daemon Error: `recv` turns Error into Err and `?` propagates it. `quotactl_fd` is now denied as well (an addition to the plan's list).
Verify command: `make lint && make test && make release`, the WP24 VM check on debian12, then `vm/hostile.sh` on debian12, ubuntu2204 and ubuntu2404.
Verify output (trimmed, real):
```
WP24 debian12: REPORT PASS x2; strace 134 successful, 14 O_PATH, 120 data opens = 120 traced   WP24 GLASSHOUSE PASS
debian12:  HOSTILE SUMMARY: 20 contained, 0 escaped; forkbomb SSH 166 ms   VM-HOSTILE debian12 PASS
  PROBE flood: CONTAINED budget drops counted: 3653592, R008: True, child read after flood: ['read'], notes: ...; 1 box process(es) were recognised by their user and cgroup because their start was not recorded
  PROBE torture: CONTAINED took 1s; notes: differ stopped at 20000 entries; ...; 2 file(s) or directories had been made unreadable inside the box; the differ restored owner access ...; decoy /home/victim/passwords.txt has 1 extra name(s) (hard links) ...; 19920 new entries; the first 1000 by name are listed
  PROBE membomb: CONTAINED ended: exit None ['the sample was stopped by the 1 GiB memory limit (oom-kill)']
ubuntu2204: HOSTILE SUMMARY: 20 contained, 0 escaped; forkbomb SSH 214 ms   VM-HOSTILE ubuntu2204 PASS
ubuntu2404: HOSTILE UNAVAILABLE-CORRECTLY PASS   VM-HOSTILE ubuntu2404 PASS
make lint: clean; make test: all ok (glasshouse lib 13 incl. hostile_trees_stay_bounded_and_honest, core display json_safe test)
```
Result: Gate M4 slice PASS (lint, tests, VM functional and adversarial runs, review fixed). The full gate (host `make test-root`) and the host Glasshouse run stay BLOCKED(E1) on Q1.

### 2026-11-14 02:10 WP26 Real-sample protocol
Did:
- `vm/build-detonation-image.sh`: a one-time build with network and no sample. It takes a Debian 12 cloud image, adds bubblewrap and the SysScope release binaries, runs sysusers, and installs the `sysscope-detonate.service` autorun, which acts only when a disc labelled SYSSCOPESAMPLE is attached. It then disables cloud-init and SSH, removes the build key, powers off cleanly from inside, and flattens the disk to `~/.cache/sysscope-vm/detonation/detonation.qcow2` (0600).
- `vm/detonation/autorun.sh` (guest): mounts the read-only disc, extracts exactly one file from the ZipCrypto archive with the password, runs `sysscope --json glasshouse run` under the daemon, and writes the report (or an error object) between marker lines to /dev/ttyS1 in raw mode. Then `poweroff -f`.
- `vm/detonate.sh ARCHIVE PASSWORD [TIMEOUT]`:
  - puts the archive, password and timeout in a read-only ISO;
  - runs QEMU with `-nodefaults -no-user-config -snapshot -nic none -display none`, the second serial port writing to a file, and no shared folders;
  - refuses without KVM, while a VirtualBox VM runs, or if its own final argument list holds any -nic other than `none`, any -netdev/-net, or a NIC or USB device;
  - kills QEMU at timeout + 60 s;
  - reads the serial file as untrusted text: capped at 64 MiB, only the marked block, CRLF-tolerant, strict JSON, shown through `sysscope glasshouse report` (escaped). The header file records the date, the archive's sha256 and the exact QEMU command line.
- `docs/REAL_SAMPLES.md`: 10 numbered steps, each with a "why" line, plus the remaining risk. No sample sources are named or linked.
Deviation: plan 6.6 step 1 asks for `~/sysscope-quarantine/` (0700). The script accepts any path and the doc tells the owner to use that folder. I may not write there (SKILL.md write allowlist), so the verify zip lives in ~/.cache/sysscope-vm/wp26.
Verify command: `make release && vm/build-detonation-image.sh`, then `(cd testkit/sim && zip -P infected ~/.cache/sysscope-vm/wp26/fake.zip fake_malware.py)`, `DETONATE_QEMU_EXTRA="-nic user" vm/detonate.sh .../fake.zip infected 30`, `DETONATE_QEMU_EXTRA="-netdev user,id=n0" vm/detonate.sh ...`, and `vm/detonate.sh .../fake.zip infected 60`
Verify output (trimmed, real):
```
vm: refusing: network option '-nic user' in the QEMU command line          refusal rc=1
vm: refusing: '-netdev user,id=n0' in the QEMU command line                refusal2 rc=1
detonate: booting the detonation guest (no network, disk changes discarded)
SysScope detonation report header
archive: fake.zip sha256 d4f2162b8665180938cd8644e0fe6f6ed17259111f9295d8c2c5ca8055c3c39e
timeout: 60s (QEMU killed at 120s)
qemu: qemu-system-x86_64 -name sysscope-detonation -nodefaults -no-user-config -machine q35\,accel=kvm -enable-kvm -cpu host -m 2048 -smp 2 -drive file=.../detonation.qcow2\,if=virtio\,format=qcow2 -snapshot -drive file=.../sample.iso\,media=cdrom\,readonly=on -nic none -display none -serial file:.../console.log -serial file:.../report.serial
Glasshouse report 1794560579-1
sample: fake_malware.py
ran 0.3 s, exited with code 0
decoys: 2 read, 20 modified, 20 renamed, 10 deleted (of 42); 1 new file(s); 1 connection attempt(s)
  ... (findings R001 R004 R005 R012, as in WP24)
detonate: report files: .../report-header.txt and .../report.json            rc=0
```
Bugs found on the way:
- The first image build lost its SSH key before `poweroff`, so it was killed rather than shut down. The guest now powers off by itself, and the build fails if it does not.
- The guest's serial tty sent `\r\n`, so the markers were missed. Fixed on both sides: raw mode in the guest, CRLF tolerance on the host.
Result: PASS. Only the harmless demo sample was used; no real sample was fetched or run.

### 2026-11-14 03:00 WP27 Act mode (experimental)
Did:
- **Daemon (`act.rs`).** `sysscoped --enable-act` (off by default; Welcome `act_enabled`). For each Act request:
  1. Authorise: the peer from SO_PEERCRED (uid and pid now kept per client) must be root or have the `sysscope-act` gid in its /proc status.
  2. `pidfd_open(tgid)` first, then re-read /proc/<tgid>/stat and compare the start ticks with the ProcKey (a recycled pid is refused).
  3. Check the protected list: pid 1, kernel threads (PF_KTHREAD, pid 2), the daemon, the requesting client itself, any ancestor of it, display servers, session managers and the GUI in the requester's session (by comm), and for non-root requesters anything whose real or saved uid is not theirs.
  4. Send the signal with `pidfd_send_signal` (STOP, CONT or KILL).
  Every request is logged to stderr (the journal under systemd) with action, target, requester uid and pid, nonce and result. Never automatic.
- **CLI.** `sysscope act pause|resume|kill PID`; a refusal exits 5 with the reason.
- **GUI.** Controls appear only when the daemon enables act mode, under an EXPERIMENTAL label. Pause is one click, with "Undo (resume)". Kill stays disabled until the pid is typed.
- **Tests.** Unit tests: stat parsing with a hostile name, protected self and pid 1, GUI kill confirmation and pause undo. `vm/tests/wp05_itest.sh` now creates the sysusers groups.
Verify command: `make lint && make test && make itest-bin`, then `vm/run.sh <d> "$(cat vm/tests/wp05_itest.sh)"` for debian12 and ubuntu2204
Verify output (real):
```
debian12 sysscope-itest-act:
test a_recycled_pid_is_refused ... ok          (ns_last_pid forced; VM-only guard)
test act_is_refused_unless_enabled ... ok
test non_root_needs_the_group_and_ownership ... ok   (nobody: no group -> "not authorised"; with group, root's process -> "could not signal"; own process -> paused)
test pause_resume_and_kill_a_workload_child ... ok   (state T, then not T, then SIGKILL; journal lines with uid 0)
test protected_processes_are_refused ... ok    (pid 1, kthreadd, daemon, ancestor, a process named Xorg in the session)
test result: ok. 5 passed
ubuntu2204 (kernel 5.15): act 5, cli 5, files 5, follow 4, lifecycle 5, network 1, proc 3, server 7, syscalls 1 -> all ok; dmesg: no new bpf/BUG/WARNING/RCU lines
debian12: all other itest binaries ok as well
```
Limit (to be recorded in THREAT_MODEL.md at WP29): a pid recycled within the same clock tick (10 ms) as the original's start cannot be told apart by start time. The test waits more than one tick.
Bug found on the way: the test assumed the dev socket is group 0; under sudo it is SUDO_GID. The test now reads the socket's group.
Result: PASS in VMs; host run BLOCKED(E1).

### 2026-11-14 04:30 Owner answers; first host root run
Did:
- **Owner answers.** Q1 A: passwordless sudo, verified from the agent shell. Q2 A: the VM line in vm/lib.sh is now guest RAM + 2 GiB (4 GiB). Q3 A: the R006 end-to-end test will use a test-only rules override.
- **`make setup`** installed the plan's packages from the Kali repositories. hyperfine is not in Kali, so it was removed from APT_PKGS; the WP19 bench will use `cargo install hyperfine` as the user.
- **First `make test-root` on the host** (kernel 6.19.14+kali): 47 of 49 pass.
- **Bug: follow-mode leak** (found only on this busy host). `sysscoped --dump --follow` attached the programs in system-wide mode and switched to follow after the /proc scan. Events from other processes in that window were recorded: 124 opens by an unrelated root process reading /var/lib/dpkg/info/*.list. Fixed: with a follow root at start, the programs attach already in follow mode with an empty set (LoadOpts.follow_at_start).
- **Still open:** the act test `non_root_needs_the_group_and_ownership` needs the `sysscope-act` group, which this host does not have (Q4).
Verify command: `make test-root` (all other test binaries), then for the fix `make release` and a manual dump following an idle process, plus the follow test 3x: `sudo -E cargo test -p sysscope-itest --release --test follow` (runner `sudo -E`), then `sudo dmesg --level=err,warn`
Verify output (real):
```
host make test-root: cli 5, files 5, lifecycle 5, network 1, proc 3, server 7, syscalls 1, act 4 of 5 (missing group) -> ok; follow 3 of 4 (leak) before the fix
leak repro before the fix: following pid 569641 -> events 1..124 from pid 569634 (Open /var/lib/dpkg/info/*.list)
after the fix: received=0 | events: 0 | from other pids: 0
follow: test result: ok. 4 passed (x3)
dmesg new err/warn after every host BPF run: none
```
Result: host root tests PASS except the one act test that needs Q4.

### 2026-11-14 06:30 WP28 R009, R011, R100
Did:
- **R009** (core `rules/procs.rs`): on Exec of an exe in class `programs` (shells and interpreters), whose parent's exe is in class `parents` (viewers, office, browsers, mail, web servers). Subject: the parent's name.
- **R011:** new optional BPF program `fentry/security_ptrace_access_check`, which emits only ATTACH-mode checks on another tgid (new EV_PTRACE / EventKind::Ptrace). It is loaded only if the kernel BTF has the function; Welcome feature "ptrace". The rule fires when the target is not in the caller's own tree and the caller is not in class `debuggers`.
- **R100** (core `baseline.rs`, experimental, `disabled = true`):
  - per-run behaviour vector (top 32 syscalls, file dir classes, destinations, children) and Jensen-Shannon divergence (base 2);
  - flags a run only after 20 runs and 6 h, above the baseline's own p99, and does not learn flagged runs;
  - bounded, versioned store at /var/lib/sysscope/baselines.json, loaded and saved by the daemon only when enabled (atomic write, 0600).
  The UI shows the rule title "Unlike itself (experimental)".
- **Fixtures:** R009 and R011 each have 3+ positive, 3 negative and 2 boundary cases (sibling attach, own parent, unknown target, debugger, own child and grandchild; renamed viewer copy, versioned interpreter).
- **Simulators:** `testkit/sim/doc_spawns_shell.py` (a renamed copy of /bin/sh named "evince" starts a shell) and `testkit/sim/ptrace_attach.py` (attach to its own child's sibling), plus the new itest `rules_e2e`. The new BPF program ran in VMs first.
Verify command: `make lint && make test`, `make itest-bin` + VM runs of wp05_itest.sh (debian12, ubuntu2204) with SYSSCOPE_SIM_DIR, then host `sudo -E cargo test -p sysscope-itest --release --no-fail-fast` and `sudo dmesg --level=err,warn`
Verify output (real):
```
make test: integrity OK; core lib incl. baseline x5 (divergence bounds/symmetry, p99 nearest rank, young/small baselines never flag then an unlike run is flagged and not learned, bounded store + JSON round trip + version check, dir classes); every_rule_fixture_matches_expected ok (R009, R011 included)
debian12 + ubuntu2204: all itest binaries ok except rules_e2e R009, where my assertion wanted "/sh" but the alert said "evince (pid 1588) started /usr/bin/dash" (real detection; assertion fixed). Re-run debian12: r009 ok, r011 ok; dmesg 0 bpf/BUG/WARNING lines
host: act 4/5 (Q4 group), cli 5, files 5, follow 4, lifecycle 5, network 1, proc 3, rules_e2e 2, server 7, syscalls 1; dmesg new err/warn: none
```
Pending: "benign corpus still within thresholds with R009/R011 on" needs the WP18 benign corpus (fp-eval), now unblocked and next.
Result: PASS.
