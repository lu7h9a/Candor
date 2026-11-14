# Architecture

How Candor is put together, as the code is now. The constants quoted here
live in `crates/candord/bpf/candor.h`, `crates/candor-core/src/limits.rs`
and `crates/candord/src/server.rs`.

## Parts

```text
crates/candor-proto/       message types, framing, byte-string escaping (no I/O of its own)
crates/candor-core/        pure logic: process table, history, rules, scoring, replay
crates/candord/            the daemon; bpf/ holds the eBPF C programs, abi.rs the only unsafe Rust
crates/candor-cli/         `candor`, the command-line client
crates/candor-gui/         `candor-gui`, the egui desktop client
crates/candor-glasshouse/  `candor-glasshouse`: sandbox helper, decoys, differ, report
crates/candor-itest/       root integration tests
testkit/                     workload generator (wl), harmless rule simulators, VM-only hostile probes
fuzz/                        cargo-fuzz targets
vm/, packaging/              test VMs, distro matrix; packages, systemd unit, sysusers
```

Two privilege domains (invariant I1):
- `candord` runs as root, with a bounded set of capabilities, and is the
  only process that loads eBPF or reads other users' `/proc`.
- The GUI and the CLI run as the user and talk only to the daemon's socket.
  The GUI refuses to run as root.

## Kernel side

eBPF programs, loaded with CO-RE (compiled once, adapted to each kernel's BTF
at load time). They only observe (I2):

| Program | Hook | Emits |
|---|---|---|
| `on_exec` | `tp_btf/sched_process_exec` | EXEC: path, (dev, ino), fileless flag, first 256 bytes of argv |
| `on_fork` | `tp_btf/sched_process_fork` | FORK (processes, not threads); follow-mode inheritance |
| `on_exit` | `tp_btf/sched_process_exit` | EXIT, once per process (`exit_seen`) |
| `on_file_open` | `fentry/security_file_open` | OPEN: resolved path (`bpf_d_path`), (dev, ino), read/write/create/truncate |
| `on_rename`, `on_unlink` | `fentry/security_inode_rename`, `_unlink` | RENAME, UNLINK |
| `on_connect`, `on_listen` | `fentry/security_socket_connect`, `_listen` | CONNECT (address), LISTEN |
| `on_ptrace_check` | `fentry/security_ptrace_access_check` | PTRACE attach attempts (optional: only if the kernel's BTF has the function) |
| `on_sys_enter`, `on_sys_exit` | `raw_tp/sys_enter`, `sys_exit` | per-process syscall counts; latency only in follow mode while someone watches |

Every event-emitting program starts with the same gate:
1. Skip the daemon itself.
2. In follow mode, skip anything outside the followed tree or cgroup.
3. Take a token from the process's budget (2,000 events/s, bursts of 4,000).
   EXEC and EXIT take no token.

Maps:

| Map | Type | Purpose | Max |
|---|---|---|---|
| `events` | ring buffer | events to the daemon | 8 MiB |
| `cfg` | array | mode, budget, flags | 1 |
| `followed_tgid`, `followed_cgroup` | hash | follow mode | 16,384 / 64 |
| `ignored_tgid` | hash | the daemon itself | 16 |
| `budget` | LRU hash | per-process tokens and drop counters, keyed (tgid, start time) | 16,384 |
| `drops` | per-CPU array | global loss counters by reason | 8 |
| `exec_stash` | LRU hash | resolved exec paths, from the open hook to the exec hook | 4,096 |
| `exit_seen` | LRU hash | one EXIT per process | 16,384 |
| `sys_count`, `sys_lat`, `sys_start` | LRU hashes | syscall counts and follow-mode latency | 65,536 / 16,384 / 16,384 |
| `scratch` | per-CPU array | buffer for paths too large for the BPF stack | 1 |

Process identity everywhere is (tgid, start time), never a bare pid (I4), and
file identity is (device, inode). Paths are display data (I5).

## Daemon threads

```text
kernel --ring buffer--> [poller] --channel 65,536 (blocks when full)--> [core]
/proc  --every 1 s----> [sampler] --channel 64----------------------->  [core]
clients <-- writer thread <-- per-client queues <-- [core] <-- commands (channel 1,024) <-- reader thread <-- [acceptor]
                                                    [core] <--> executable-check pool (up to 4 threads, 50 ms deadline)
                                                    [core] <--> Glasshouse helper threads (one run at a time)
```

- **The core thread** owns all state (`candor-core::State` and the rule
  engine). There are no locks around state; other threads send messages.
- **The poller** decodes ring-buffer records. When the core falls behind, the
  poller blocks, the ring buffer fills, and the kernel counts the drops: there
  is exactly one place where events are lost, and it is counted (I3).
- **Executable and script checks** run on a small pool with a deadline, so a
  hung filesystem cannot stall detection. A check that times out answers
  "not trusted".
- **Every 500 ms** the core builds a snapshot, but only when someone is
  subscribed. **Every second** it runs the time-window rules and score
  decay, and picks up kernel loss counters. Event-driven rules run on each
  event.

## Socket and clients

- `/run/candor/candor.sock`, mode `0660 root:candor`, peer identity
  from `SO_PEERCRED`.
- Frames: a 4-byte length, then JSON. A client frame is at most 1 MiB, a
  daemon frame at most 16 MiB.
- At most 8 clients, and 4 per non-root user. A client must say Hello within
  10 seconds.
- **Per-client queues:**
  - snapshots: only the latest is kept;
  - events: 4,096, oldest dropped first, counted;
  - alerts: 256, likewise;
  - replies: 64.
  
  A client that does not read for 5 seconds is disconnected.
- Clients send bytes, never paths: the daemon does not open a path a client
  names (I12).

## Detection

`candor-core` is pure: no I/O, no clock, no threads (I7). Time comes only
from event timestamps, so a recording replays to the same findings
(`candor replay`).

- Rules are Rust functions over the state. Their thresholds, path classes and
  texts live in `rules.toml`, and the allowlist in `allow.toml`; both are
  built in and can be overridden from `/etc/candor/`.
- Each finding carries the ids of the events that justify it (I9).
- A process's score combines its findings with a noisy-OR (0–100) and
  halves every 10 minutes. Bands: suspicious from 30, high from 60.
- An allowlist entry applies only when the executable (and, for an
  interpreter, its script) is root-owned and not writable by others. This is
  checked through `/proc/<pid>/exe` and `/proc/<pid>/root`.

## Glasshouse

```text
client --sample bytes--> candord --systemd-run--> helper unit (root)
   helper: prepares a tmpfs run dir: decoy home, synthetic /etc, baseline, seccomp filters
   helper --systemd-run--> sandbox unit (user candor-box, cgroup traced by the daemon)
          bubblewrap: new namespaces, /usr read-only, no network but loopback,
          three seccomp filters, no capabilities, NoNewPrivileges, resource limits
   sample exits or times out --> differ (as candor-box): before/after of every decoy
   --> report: decoys read/modified/renamed/deleted, new files, connection attempts, findings
```

The daemon follows the sandbox's cgroup, so everything the sample does is
traced even while the rest of the system is in follow mode. The helper and the
sandbox are separate systemd units, so the daemon itself needs neither
CAP_SETUID nor CAP_SYS_ADMIN.

## Hardening

The systemd unit gives the daemon five capabilities: CAP_BPF, CAP_PERFMON,
CAP_SYS_PTRACE, CAP_KILL and CAP_CHOWN. It also sets no network,
`ProtectSystem=strict`, private /tmp and devices, a syscall deny list and
more. Each capability was shown to be necessary by removing it and running
the tests ([THREAT_MODEL.md](THREAT_MODEL.md), section 4).
