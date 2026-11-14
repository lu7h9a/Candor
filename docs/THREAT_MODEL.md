# SysScope threat model (plan WP29 d)

This document says what SysScope protects, where the trust boundaries are,
what each kind of attacker can and cannot do, and which risks remain. It is
written against the code as of WP29; every "cannot" below is either enforced
by the kernel or covered by a named test. Anything that is only intended,
not tested, is listed under residual risks.

## 1. Assets

| Asset | Why it matters |
|---|---|
| A1 The host and the owner's account | SysScope runs a root daemon; a bug in it is a root bug. |
| A2 What the daemon sees | Command lines, opened paths, connection addresses and memory maps of every process, including root's. Equivalent to read access to a lot of private activity. |
| A3 Detection integrity | Findings must not be silently suppressible by the processes they are about. |
| A4 The owner's session | Act mode can stop processes; a false positive must never cost the session (D19). |
| A5 Glasshouse outputs | Reports are parsed and shown on the host; a sample controls their content. |

## 2. Trust boundaries

| Boundary | Direction of untrusted data | Controls |
|---|---|---|
| B1 kernel ring buffer -> daemon | records built by BPF from traced processes' data | fixed-size structs, length-checked decoder (`abi.rs`, fuzzed), paths and argv are display bytes only (I5), escaped on output (I10) |
| B2 Unix socket -> daemon | client frames | socket `0660 root:sysscope` in a `0750` directory; SO_PEERCRED; u32 frame length capped (`MAX_CLIENT_FRAME`), typed serde decoding (unknown message types refused; unknown fields ignored on purpose so versions can add fields, plan D2), fuzzed; 8 clients; Hello within 10 s; per-client bounded queues; the daemon never opens a client path (I12, D25) |
| B3 Glasshouse helper -> daemon | JSON lines from the helper that runs next to the sample | line length cap, `deny_unknown_fields`, bounded counts (MAX_BOX_PROCS, MAX_CREATED, MAX_PATH_KEPT), fuzzed parser |
| B4 sample -> host filesystem | files the sample leaves in its run directory | differ runs as `sysscope-box`, never follows symlinks (`openat` beneath, O_NOFOLLOW per component), regular files only, caps, run dir removed afterwards |
| B5 detonation VM -> host | serial-port report | 64 MiB cap, same strict types, escaped display; no network, no shared folders, `-snapshot` (D18) |
| B6 config files -> daemon | `/etc/sysscope/*.toml` | root-owned only (D24); clients cannot change them; loader fuzzed |
| B7 saved files -> CLI/GUI | recordings and reports chosen by the user | bounded line reader, strict parsing, fuzzed |

## 3. Attackers

### 3.1 Unprivileged local process (malware running as the user, or as another user)

Can:
- Generate events at any rate. Beyond the per-process token bucket (2000/s, burst 4000) its own OPEN/RENAME/UNLINK/CONNECT/PTRACE events are dropped and counted (I3, D10); R008 flags three consecutive seconds of drops. EXEC is exempt from the budget (review F1), so a burst cannot hide what program it runs.
- Choose its own name (`comm`), argv and file paths, including control bytes, bidi characters and very long names. All of these are display data, escaped (I10), never identity (I4, I5).
- Create a user and mount namespace or chroot and make its executable's path look like a system path (review F4). Trust and the allowlist are not fooled: they check the real file through `/proc/<pid>/exe` (root-owned, not group/world-writable, in a root-owned directory). R002 and the displayed path are fooled; NEEDS_USER Q7.
- Fill the shared ring buffer together with other processes; then everyone's events are dropped and counted (I3).
- Read files the kernel lets it read. Denied opens never reach `security_file_open`, so a refused attempt to read `/etc/shadow` is not seen.

Cannot:
- Load BPF, read the daemon's memory or other users' /proc entries, connect to the socket (not in group `sysscope`), or change rules and allowlists (root-owned files).
- Get onto the allowlist by naming or placing itself: allowlist entries need the verified root-owned executable, and interpreter entries also the verified root-owned script given without value-taking options (review F6). Debugger exemption for R011 needs the verified system executable (review F5).

### 3.2 Sandboxed sample (Glasshouse)

See plan 6.5 for the per-attack table; each row has a probe in `testkit/hostile` (WP25, run only in a VM). Summary: no network but loopback; a fresh pid, mount, ipc, uts and net namespace; only /usr read-only, a synthetic /etc and a decoy home; uid `sysscope-box` with no capabilities, NoNewPrivileges, three seccomp filters (high-risk syscalls EPERM, clone3 ENOSYS, x32 killed); cgroup limits (tasks, memory, CPU, file size, LimitCORE=1 so a piped core_pattern helper never runs); wall-clock timeout and cgroup kill.

Cannot: reach the daemon socket, X11, D-Bus or abstract Unix sockets; see host processes; gain privileges through setuid binaries; persist after the run.

Can: use any kernel bug reachable through the allowed syscalls, CPU side channels, and detect that it is sandboxed. This is why Glasshouse is not for real malware (I13, plan 6.4 text) and real samples run only in the detonation VM (D18).

### 3.3 Member of the `sysscope` group

The group exists so that the owner's GUI and CLI can talk to the daemon.

Can:
- See everything the daemon sees about every process (A2): command lines, open paths, connections, findings. Memory maps only of processes running under its own uid (root sees all), the kernel's rule for `/proc/<pid>/maps`. Membership is therefore close to root-level read access to process activity; grant it only to people you would show that to.
- Switch the daemon into follow mode, which limits detection for every client (review F9). Each request is logged with uid and pid; the snapshot shows the mode to every viewer. NEEDS_USER Q6 decides whether this needs `sysscope-act`.
- Upload a Glasshouse sample (bytes only, size-capped) and read reports.
- Use up to 4 of the 8 client slots; a slot without Hello is freed after 10 s. A Glasshouse upload must average 64 KiB/s or its slot is freed.

Cannot:
- Change rules or allowlists (D24), make the daemon open a path (I12), act on processes without also being in `sysscope-act` (and then only on processes it could signal itself, unless root).

### 3.4 Member of `sysscope-act`

Can pause, resume or kill processes it could signal itself, through the daemon, logged with uid and pid. Protected: pid 1, kernel threads, the daemon, the requesting client and its ancestors, and (by name, in the requester's session) the display server, session manager and SysScope GUI. The target is opened with a pidfd and its start time checked, so a recycled pid is refused (tested in a VM by forcing `ns_last_pid`).

Residual: membership is read from `/proc/<requester pid>/status` at act time (review F12); if the client handed its socket to another process, the check reads that process's groups.

### 3.5 Root

Root can unload SysScope, edit its rules and read its memory. SysScope does not defend against root and does not claim to; a rootkit loaded before or after SysScope can hide from it.

## 4. Daemon privileges (systemd unit)

`packaging/systemd/sysscoped.service`. The capability set is the smallest
with which every root integration test passes while the daemon runs inside
the unit's full sandboxing (`scripts/unit-wrap.sh` starts it as a transient
service with the same settings; `SYSSCOPE_ITEST_WRAP` makes every itest use
it). Each capability was removed in turn (section 6).

| Capability | Needed for | Without it (measured) |
|---|---|---|
| CAP_BPF | loading programs and maps | `bpf_object__probe_loading(): -EPERM`, daemon does not start |
| CAP_PERFMON | tracing programs (fentry, tp_btf, raw_tp), `bpf_d_path`, kernel memory reads | `prog 'on_exec': BPF program load failed: -EPERM` |
| CAP_SYS_PTRACE | other processes' `/proc/<pid>/{exe,maps,io,ns}` | `cannot read /proc/1/ns/pid: Permission denied` |
| CAP_KILL | act mode on another user's process | act test `non_root_needs_the_group_and_ownership` fails (only used with `--enable-act`) |
| CAP_CHOWN | giving the socket, its directory and reports to group `sysscope`, run directories to `sysscope-box`; root is not a member of those groups | `Operation not permitted` while creating the socket |

Not needed although the plan expected them: CAP_DAC_READ_SEARCH (all 47
tests pass without it; executables in directories root cannot enter are
simply not trusted, which is the conservative answer) and CAP_SYS_RESOURCE
(kernels from 5.11 charge BPF memory to the cgroup, not RLIMIT_MEMLOCK;
every supported distro is newer).

Other settings: NoNewPrivileges, ProtectSystem=strict with ReadWritePaths
for `/run/sysscope` and `/var/lib/sysscope` only, ProtectHome=read-only,
PrivateTmp, RestrictAddressFamilies=AF_UNIX AF_NETLINK, IPAddressDeny=any,
PrivateNetwork (its own network namespace: no network at all, I11 and D23),
PrivateDevices, ProtectClock, ProtectHostname, ProtectKernelLogs,
ProtectKernelModules, ProtectKernelTunables, ProtectControlGroups,
RestrictNamespaces, RestrictRealtime, MemoryDenyWriteExecute, UMask=0027,
SystemCallFilter=~@clock @cpu-emulation @module @obsolete @raw-io @reboot
@swap, MemoryMax=512M, SystemCallArchitectures=native, LockPersonality,
RestrictSUIDSGID.

The Glasshouse helper, its availability check and the startup unmount of a
stale run tmpfs run as separate transient units started through systemd,
so they are not bound by these settings and the daemon needs neither
CAP_SETUID nor CAP_SYS_ADMIN. Two bugs were found this way and fixed: the
availability check ran inside the daemon (so Glasshouse was always
"unavailable" under the unit) and the sweep's `umount` could not work
without CAP_SYS_ADMIN.

## 5. Residual risks

| Risk | Status |
|---|---|
| Kernel or bubblewrap vulnerability reachable from a sample | accepted; Glasshouse is not for real malware; detonation VM for real samples |
| Side channels, sandbox detection | accepted (plan 6.5) |
| Follow mode switched by any socket-group member | open, NEEDS_USER Q6; logged |
| Ring buffer shared by all processes: a flood causes counted loss for everyone | accepted, counted (I3), R008 |
| Denied opens of credential files are not observed | accepted; the hook runs after permission checks |
| Act group membership read at act time from /proc | low; fix with SO_PEERGROUPS at connect (review F12) |
| Glasshouse relies on seccomp alone to forbid nested user namespaces | low; `bwrap --disable-userns` as a second layer is planned |
| Pid reuse within one clock tick (10 ms) between two processes | accepted; start_ticks granularity, documented in plan D11 |
| A stalled filesystem (FUSE, network) under a traced program's path | each executable check waits at most 50 ms on a pool of at most 4 workers; then "not trusted" (review 2 finding 1) |
| A program that exits before the daemon can inspect /proc/<pid> (microseconds) | its trust and private-view checks fail: it is treated as untrusted (the safe answer) and its path is not marked |
| Path shown for a program in a private mount namespace is its own view | trust checks resolve through /proc/<pid>/root (review 2 finding 5); the displayed path and R002's prefix test still use the program's view: NEEDS_USER Q7 |
| Glasshouse adopts a process that vanished before its cgroup could be read, on its uid alone | accepted: only the sandbox runs as `sysscope-box`; refusing would lose short-lived box processes (review 2 finding 14) |
| Act and maps decisions use SO_PEERCRED uid; act group membership is read from /proc/<pid>/status at act time | low; SO_PEERGROUPS at connect needs unsafe code outside abi.rs (I14) (review F12, review 2 finding 3) |
| The kernel skips a probe run when the probe is already running on that CPU (more often on fully preemptible kernels: Arch, Fedora) | counted by the kernel per program and shown as "skipped by the kernel" (Loss.missed); which process lost the event is not known (WP31) |
| Root | out of scope (3.5) |

## 6. Measurements (2026-11-14, host kernel 6.19.14, systemd 260)

- `systemd-analyze security --offline=true packaging/systemd/sysscoped.service`:
  5.9 MEDIUM with the plan's settings, 2.2 OK with the final unit. The
  remaining exposure is inherent: root, CAP_BPF/PERFMON/SYS_PTRACE/KILL/
  CHOWN, full /proc (ProtectProc would hide the processes it monitors),
  AF_UNIX/AF_NETLINK, no PrivateUsers.
- Capability probe (target/cap-probe/*.log): all 47 root itests with the
  daemon in the unit: PASS. Removing CAP_BPF, CAP_PERFMON, CAP_SYS_PTRACE or
  CAP_CHOWN: the daemon does not start. Removing CAP_KILL: one act test
  fails. Removing CAP_DAC_READ_SEARCH or CAP_SYS_RESOURCE: PASS (dropped).
- Glasshouse demo (WP24 host script) with the daemon in the final unit:
  REPORT PASS, every data open of the box attributed, loss 0.
- Stale run tmpfs at daemon start, daemon in the unit: before the fix
  "STILL MOUNTED", after the fix unmounted and removed.
- Fuzzing (WP29 b): six targets, 10 min each, zero crashes.
- `cargo audit`: 0 vulnerabilities in 392 crates; `cargo deny check`: clean.
