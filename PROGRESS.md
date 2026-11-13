# PROGRESS

## Current state
Updated: 2026-11-13 06:05 IST
Milestone: M0   Current WP: M1/M2 gate slice   Status: IN_PROGRESS
Next action: run `make lint test vm-test`, then the fresh-subagent adversarial review of the repo against the SKILL.md invariants; fix findings with regression tests
Open questions for owner: Q1, Q2, Q3
Tree state: clean after WP00 commit
Last green gate: none yet (every gate includes `make test-root`, which needs Q1)

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

## Deviations from the plan
- 2026-11-13 WP13: explanations and event times in the CLI are shown in UTC (tz_offset 0): local time zone needs either libc (unsafe) or a zoneinfo parser; noted in docs/UNVERIFIED.md for WP20/WP33
- 2026-11-13 WP12: EXIT is emitted by the first thread that sees signal->live == 0, de-duplicated per (tgid, start) with an LRU map; the VM showed two EXITs when a joined thread was still inside do_exit while the main thread exited - refines the WP04 choice (recorded in VERIFIED.md)
- 2026-11-13 WP06: OPEN events are not emitted for exec-opens (`__FMODE_EXEC`: the binary, its interpreter, ld.so); they feed the exec-path stash and are represented by the EXEC event - plan silent; avoids double counting exec as open
- 2026-11-13 WP17: limits.rs gained MAX_EVIDENCE_IDS (1000), WINDOW_ENTRIES (4096), BEACON_POINTS (64) - new caps required by I8 for finding evidence lists and rule windows; no existing value changed - allowed: plan 4.6 is silent on these
- 2026-11-13 WP17: PLAN CONFLICT (not resolved, recorded): 5.7(2) says network simulators talk only to 127.0.0.0/8 and WP17 specifies `sim/beacon.py` with a local listener, but R006 (5.4) only counts non-loopback destinations, so that simulator cannot trigger R006. Kept R006 exactly as specified; beacon.py is loopback-only as specified; R006 positives are covered by replay fixtures with 10.1.2.3 / 93.184.216.34. The end-to-end R006 check (blocked by Q1 anyway) needs an owner decision or a test-only rules override that allows loopback - raised as NEEDS_USER Q3 (E6).
- 2026-11-13 WP17: R005 "for one process tree" implemented as: each event counts for its process and for that process's direct parent (bounded; avoids flagging systemd for unrelated services). R005 simulator files live in its own dir, so the end-to-end test must add that dir to R005 `roots` via a test rules override (like R004).
- 2026-11-13 WP15: added field `subject` to protocol `Finding` (it is part of the de-duplication key and of the "To silence" allowlist line in 5.6). Plan 4.5 says additive fields do not bump `proto`, and also that changing a golden file requires a bump; treated as additive: `#[serde(default)]` so older peers still decode, goldens Alert/Detail/GhReport.json regenerated (diff = exactly one `"subject"` line each), proto stays 1 - allowed by the additive-field rule
- 2026-11-13 WP11: plan says measure the 1M-event replay with `/usr/bin/time -v` -> the `time` package is not installed and not pre-authorised, so the replay example prints VmHWM from /proc/self/status (the value time -v reports as maximum RSS) and its own wall time - allowed: same measurement, different reader
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
