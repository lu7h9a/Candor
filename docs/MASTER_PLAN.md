# SysScope - MASTER PLAN

Audience: Claude Opus in Claude Code, building alone from an empty folder. The owner is absent. Rules of work are in `.claude/skills/sysscope/SKILL.md`; when to ask is in `docs/ESCALATION.md`.

`[VERIFY]` marks a claim about kernel or library behaviour the architect believes but did not test. Check it before relying on it; log the result in `docs/VERIFIED.md`.

---

## 1. What we are building

A Linux desktop tool that shows what every process is doing (CPU, memory, syscalls, files, network, children) and flags suspicious behaviour with evidence. Parts:

- `sysscoped` - root daemon: loads eBPF, samples /proc, keeps state, runs detection, serves a Unix socket.
- `sysscope` - unprivileged CLI client (also the headless test surface).
- `sysscope-gui` - unprivileged egui desktop client.
- Glasshouse - run an untrusted program in a sandbox full of decoy files and report what it touched.

Product statement (use this wording in README and UI): "SysScope shows what programs on your Linux machine are doing and explains why some behaviour looks suspicious. It is a visibility tool with explainable heuristics, not an antivirus, and it cannot be relied on to stop or contain malware."

## 2. Fixed facts about the environment

- Host: Kali Linux, kernel `6.19.14+kali-amd64`, x86_64, X11, BTF present (`/sys/kernel/btf/vmlinux`, `CONFIG_DEBUG_INFO_BTF=y`), `/dev/kvm` present, VirtualBox kernel modules also loaded.
- Passwordless sudo is expected. `gh` is logged in. Repo is private until the owner launches.
- Working name `sysscope`. The owner will choose the final name later; WP33 provides a rename script.
- Supported: x86_64, kernel >= 5.15 with BTF, systemd, cgroup v2. Primary target is the host. Distros for release: Debian 12+, Ubuntu 22.04+, Fedora (current), Arch, Kali.
- Pre-authorised packages (official Kali repos only): build-essential, clang, llvm, lld, libelf-dev, zlib1g-dev, libzstd-dev, pkg-config, bpftool, linux-headers for the running kernel, libbpf-dev, make, git, python3, strace, qemu-system-x86, qemu-utils, cloud-image-utils, genisoimage, openssh-client, xvfb, mesa-utils, libgl1-mesa-dri, libxkbcommon-dev, libwayland-dev, libx11-dev, libxcursor-dev, libxi-dev, libxrandr-dev, libfontconfig-dev, bubblewrap, libseccomp-dev, clang-format, rpm, dpkg-dev, fakeroot, jq, hyperfine. Rust via the official rustup installer (stable). Cargo tools via `cargo install`: cargo-deb, cargo-generate-rpm, cargo-fuzz (needs nightly toolchain installed side by side for fuzzing only), cargo-audit, cargo-deny.

## 3. Decision record

| # | Decision | Rejected alternatives | Reason |
|---|---|---|---|
| D1 | Root daemon + unprivileged GUI/CLI over a Unix socket | Root GUI; setuid/cap'd GUI binary; pkexec per action | A GUI toolkit as root is a large attack surface and breaks on Wayland/X auth. Split also gives a headless test surface for free. |
| D2 | IPC = Unix stream socket, frames of `u32 LE length + UTF-8 JSON`, `SO_PEERCRED` auth, socket `0660 root:sysscope` | gRPC/tonic (async, large Rust surface); D-Bus (poor for streams); bincode/postcard (opaque, brittle versioning); shared memory | Debuggable with `socat`, version-tolerant, small code. Volume is low because the daemon aggregates (D5). |
| D3 | No async. Std threads + bounded channels (`crossbeam-channel`) | tokio | Smallest teachable Rust surface; workload is a handful of long-lived threads. |
| D4 | CO-RE eBPF in C via libbpf-rs + libbpf-cargo skeleton, object embedded in the daemon. BTF is required; no non-BTF fallback | Aya (pure Rust BPF: harder for a Rust beginner, less reference material); BCC (runtime clang, heavy); kernel module; non-BTF tier with tracepoint-only probes | One binary, portable across kernels, the owner knows C. Every supported distro ships BTF, and a second probe tier doubles the test matrix. |
| D5 | Daemon owns state and detection; clients are thin viewers. Daemon sends full process snapshots at 2 Hz, per-process detail on request, and bounded event streams | Raw event firehose to GUI; delta snapshots | Detection must run without a GUI. Full snapshots cannot desync and are ~150 KB at 500 processes. |
| D6 | File opens via `fentry/security_file_open` + `bpf_d_path`; rename/unlink via `fentry/security_inode_rename` / `security_inode_unlink` | `sys_enter_openat` tracepoints (TOCTOU on the user pointer, relative paths, dirfd resolution); kprobes on `vfs_*` (signatures change across kernels); BPF LSM programs (needs `lsm=bpf` boot parameter, not default everywhere) | Kernel-resolved object, no user-memory race, covers io_uring opens `[VERIFY]`, stable prototypes. |
| D7 | Outbound connect via `fentry/security_socket_connect`; listen via `fentry/security_socket_listen` | `sys_enter_connect` tracepoint (user sockaddr race); `tcp_v4_connect` kprobes (TCP only); `inet_sock_set_state` (softirq context, wrong pid) | Address is already copied into kernel memory, process context, all families. Inbound accept and unconnected UDP are deferred (blind spot, documented). |
| D8 | Syscall counts aggregated in a kernel per-CPU map by `raw_tp/sys_enter`; latency only for followed processes; never per-syscall events | Per-syscall ring-buffer events; `syscalls:*` per-syscall tracepoints | Syscalls are the hottest path; events would cost far more than the workload itself. |
| D9 | Follow mode enforced in kernel: `followed_tgid` map with fork inheritance, `followed_cgroup` map for Glasshouse, `cfg.mode` gate at the top of every program | Userspace filtering | Bounded overhead when following one tree; cannot be flooded by unrelated processes. |
| D10 | Loss handling: one 8 MiB ring buffer; kernel-side per-tgid token bucket; all drops counted in kernel maps; userspace decode channel blocks rather than drops; per-client queues drop-oldest with counters | Unbounded userspace queues; per-CPU perf buffers; silent drop | Exactly one place where events are lost under overload (the kernel), and it is counted. A flooding process loses only its own events and is itself flagged (R008). |
| D11 | Identity: `ProcKey{tgid,start_ticks}`, files `(dev,ino)`, paths as escaped byte strings | pid; path strings | Pid reuse and path games are the standard ways tracers get fooled. |
| D12 | CPU/memory/threads/IO totals from /proc at 1 Hz; per-file bytes only for followed processes via gated `fexit/vfs_read|vfs_write` | System-wide vfs_read/write hooks; scheduler tracepoints for CPU | /proc is free and exact enough for charts. vfs hooks system-wide are too hot. |
| D13 | State is in memory with fixed retention; optional session recording to a JSONL file | SQLite/embedded DB | A weekend-buildable core; recording file doubles as test fixture format. |
| D14 | Detection = Rust rule functions over core state, thresholds/paths in `rules.toml`, noisy-OR score with time decay, allowlist keyed by root-owned exe path | Sigma/YARA-style DSL; ML classifier; additive score | Explainable, bounded 0-100, testable by replay. A DSL is a second product. |
| D15 | Anomaly ("unlike itself") score ships later (WP28) as experimental and off by default | Shipping it in v0.1 | It needs hours of baseline per program and is the main false-positive source. |
| D16 | Glasshouse = bubblewrap inside a systemd transient service running as a dedicated unprivileged user, traced by cgroup id | Hand-rolled namespaces in Rust; Docker/Podman; firejail; running as the invoking user | Reuses audited isolation code; PID 1 does the privilege drop; cgroup membership cannot be escaped, so tracing is race-free. |
| D17 | Glasshouse network: none (loopback only) | NAT with firewall; fake-internet sinkhole | Only fully safe default. Connect attempts are still observed at the hook, which is what the demo needs. Sinkhole is a post-launch idea. |
| D18 | Real samples: only inside a disposable QEMU/KVM guest with no network; report leaves the guest as text over a serial port | Running on the host in Glasshouse; shared folders; mounting guest disks on the host | Namespaces share the host kernel. Mounting an attacker-written filesystem on the host is itself an attack surface. |
| D19 | Act mode (pause/resume/kill a process) is experimental: daemon flag `--enable-act`, separate group `sysscope-act`, pidfd-based, protected list, never automatic | Auto-kill on detection; always-on act | A false positive must never cost the user their session. |
| D20 | GUI: eframe/egui with the glow (OpenGL) backend, `egui_plot`, `egui_extras` tables; UI is a pure function of a view-model | GTK/Qt bindings; Tauri/web; iced; wgpu backend | Immediate mode keeps Rust simple; glow renders under Xvfb with llvmpipe for headless screenshots. |
| D21 | Packaging: .deb, .rpm, Arch PKGBUILD, tarball + install script; built on the oldest supported glibc. Service installed but NOT enabled by default | AppImage/Flatpak/Snap (sandboxed formats cannot load eBPF or install a system service); fully static musl (GUI needs system GL/X libs); enabled-by-default daemon | A system-wide monitor must be an explicit opt-in. |
| D22 | License MIT for Rust; BPF C `Dual MIT/GPL` | GPL-3.0 for all; Apache-2.0 | Owner's choice; kernel needs a GPL-compatible string for the helpers used. |
| D23 | No telemetry, no update check, no network I/O at all, enforced by systemd unit restrictions and a test | Opt-in telemetry | A tool that sees everything on a machine must not talk to anyone. |
| D24 | Allowlists and rules are root-owned files under `/etc/sysscope/`; clients cannot change them | Editing through the GUI | Otherwise any member of the socket group could silence detection. |
| D25 | Clients upload Glasshouse samples as bytes; the daemon never opens client-supplied paths | Passing a path; passing an fd via SCM_RIGHTS | Removes the confused-deputy class entirely with the least code. |

## 4. Architecture

### 4.1 Repository layout

```
crates/sysscope-proto/      wire types, framing, escaping (no I/O beyond Read/Write traits)
crates/sysscope-core/       pure: process table, time series, retention, rule engine, scoring, replay
crates/sysscoped/           daemon binary; bpf/ (C), build.rs (skeleton), abi.rs (only unsafe), proc sampler, server
crates/sysscope-cli/        binary `sysscope`
crates/sysscope-gui/        binary `sysscope-gui`: model.rs (pure), net.rs (reader thread), ui/*.rs
crates/sysscope-glasshouse/ binary `sysscope-glasshouse` (root helper + stage2 stub) and lib (decoys, differ, report)
crates/sysscope-itest/      root integration tests, drives testkit
testkit/wl/                 C workload generator with exact ground truth
testkit/sim/                harmless behaviour simulators (Python 3 stdlib only)
testkit/hostile/            sandbox attack probes (VM only)
fixtures/                   recorded/synthetic event files + expected outputs
vm/                         VM harness scripts, cloud-init, detonation scripts
packaging/                  systemd unit, sysusers, deb/rpm/arch metadata, install.sh
docs/                       plan, VERIFIED.md, UNVERIFIED.md, THREAT_MODEL.md, etc.
```

### 4.2 Threads and data flow (daemon)

```
kernel BPF --ringbuf--> [T1 poller: decode] --bounded chan 65536, blocking send--> [T3 core]
/proc      ---1 Hz----> [T2 sampler]        --bounded chan 64, latest-wins------->  [T3 core]
clients    <--per-client writer thread <-- per-client queues <-- [T3 core] <-- commands -- [T4 acceptor + per-client reader]
```

- T3 is the single owner of all state (`sysscope-core::State`). No locks around state; other threads communicate by message.
- T1 blocks when the channel is full; the ring buffer then fills and the kernel counts drops (D10).
- Per-client queues: snapshot slot (latest wins), event queue (4096, drop-oldest, counter), alert queue (256, drop-oldest, counter). A client whose socket write stalls for 5 s is disconnected. Max 8 clients.
- T3 tick: every 500 ms build a Snapshot; every 1 s run time-window rules and decay; on every event run event-driven rules.

### 4.3 Kernel side

Maps (sizes are constants in `sysscope.h`):

| Map | Type | Key -> value | Max |
|---|---|---|---|
| `events` | RINGBUF | - | 8 MiB (configurable at load for tests) |
| `cfg` | ARRAY[1] | mode (0 system-wide, 1 follow-only), budget rate, flags | 1 |
| `followed_tgid` | HASH | tgid -> follow_id | 16384 |
| `followed_cgroup` | HASH | cgroup id -> follow_id | 64 |
| `ignored_tgid` | HASH | tgid -> 1 (the daemon itself) | 16 |
| `budget` | LRU_HASH | tgid -> {tokens, last_refill_ns, dropped} | 16384 |
| `drops` | PERCPU_ARRAY | reason index -> count (ringbuf_full, budget, scratch) | 8 |
| `sys_count` | PERCPU_HASH (LRU) | {tgid, nr} -> count | 65536 |
| `sys_lat` | LRU_HASH | {tgid, nr} -> {count, total_ns, max_ns} (followed only) | 16384 |
| `sys_start` | LRU_HASH | pid_tgid -> enter ts (followed only) | 16384 |
| `file_io` | LRU_HASH | {tgid, dev, ino} -> {rbytes, wbytes, rcalls, wcalls} (followed only) | 32768 |
| `scratch` | PERCPU_ARRAY[1] | path/event scratch buffer | 1 |

Programs:

| Program | Attach | Emits / updates | Required? |
|---|---|---|---|
| exec | `tp_btf/sched_process_exec` | EXEC: exe path, exe (dev,ino), nlink==0 flag (fileless), first 256 bytes of argv from `mm->arg_start`, uid | required |
| fork | `tp_btf/sched_process_fork` | FORK (process-level only: when child pid == child tgid); follow inheritance | required |
| exit | `tp_btf/sched_process_exit` | EXIT when the exiting thread is the group leader `[VERIFY: choose the signal that means "process gone", see WP04]`; remove from followed | required |
| open | `fentry/security_file_open` | OPEN: d_path, (dev,ino), f_flags/f_mode | required |
| rename | `fentry/security_inode_rename` | RENAME: (dev,ino), old leaf+parents, new leaf+parents | required |
| unlink | `fentry/security_inode_unlink` | UNLINK: (dev,ino), leaf+parents | required |
| connect | `fentry/security_socket_connect` | CONNECT: family, addr, port, sock type/protocol | required |
| listen | `fentry/security_socket_listen` | LISTEN: bound addr, port | optional |
| sys_enter / sys_exit | `raw_tp/sys_enter`, `raw_tp/sys_exit` | sys_count always (if enabled); sys_lat for followed | optional (config `syscalls = off|count`) |
| vfs_read / vfs_write | `fexit/vfs_read`, `fexit/vfs_write` | file_io for followed only | optional |

Every program starts with the gate, in this order: (1) skip if tgid in `ignored_tgid`; (2) if `cfg.mode == 1`, skip unless tgid in `followed_tgid` or current cgroup id in `followed_cgroup`; (3) for event-emitting programs, take one token from `budget[tgid]` (default 2000 events/s, burst 4000); on empty, increment `budget[tgid].dropped` and `drops[budget]`, return.

Event ABI (little-endian, fixed header, one struct per kind, all `_Static_assert`ed):

```
struct ev_hdr { u64 ts_boot_ns; u64 start_boot_ns; u32 tgid; u32 pid; u32 uid; u16 kind; u16 flags; };
kinds: 1 EXEC 2 FORK 3 EXIT 4 OPEN 5 RENAME 6 UNLINK 7 CONNECT 8 LISTEN
flags: bit0 PATH_TRUNCATED, bit1 ARGV_TRUNCATED, bit2 FILELESS, bit3 KTHREAD
PATH_CAP = 512 bytes; DENTRY_WALK_MAX = 16 components; ARGV_CAP = 256 bytes
```

If `bpf_d_path` fails or exceeds PATH_CAP: emit the leaf name with PATH_TRUNCATED set. Rename/unlink paths are built by a bounded walk of `d_parent` (filesystem-relative, no mount prefix); the daemon prefers a path already known for that `(dev,ino)` from an earlier OPEN and otherwise prefixes the mount point from `/proc/self/mountinfo` by `dev`, marking it "approximate".

### 4.4 Identity and time

- `start_ticks = start_boot_ns / (1_000_000_000 / CLK_TCK)`. With CLK_TCK = 100 this equals field 22 of `/proc/<pid>/stat` `[VERIFY in WP10: compare for 200 live processes; must match exactly]`. This lets BPF-sourced and /proc-sourced processes share a key.
- All event times are CLOCK_BOOTTIME ns. The daemon computes `boot_to_wall_ns` once at start and sends it in `Welcome`; clients convert for display.

### 4.5 Wire protocol v1 (`sysscope-proto`)

Frame: `u32 LE length` then that many bytes of UTF-8 JSON. Max frame: 1 MiB client->daemon, 16 MiB daemon->client. Oversize or malformed frame = `Error` then close. Every message is an object with `"t"` (type tag). Unknown fields are ignored; unknown `"t"` from a client = `Error{code:"unknown_type"}`.

Byte strings (paths, argv, comm) are JSON strings with this reversible escaping: backslash -> `\\`; any byte < 0x20, 0x7F, or any byte that is not part of a valid UTF-8 sequence -> `\xHH` (uppercase hex). Type name `BStr`. Display code shows them as-is (already safe).

Client -> daemon:
```
Hello{proto:1, client:"gui|cli", version}
Subscribe{snapshots:bool, alerts:bool, events:"none"|"all"|{proc:ProcKey}}
Follow{root:ProcKey} | Unfollow{}
GetDetail{proc:ProcKey, maps:bool}
GhUploadBegin{name:BStr, size:u64} | GhUploadChunk{seq:u32, b64:string<=64KiB raw} | GhRun{args:[BStr], timeout_s:u32} | GhCancel{}
Act{proc:ProcKey, action:"pause"|"resume"|"kill", nonce:string}        (only if daemon has --enable-act)
Ping{n}
```
Daemon -> client:
```
Welcome{proto:1, daemon_version, kernel, boot_to_wall_ns, features:[string], act_enabled:bool}
Snapshot{seq, ts_ns, mode:"system"|{follow:ProcKey}, procs:[ProcRow], loss:Loss}
Events{events:[Event], client_dropped:u64}
Alert{finding:Finding}
Detail{proc, series:{t:[u64],cpu:[f32],rss:[u64]}, recent:[Event], files:[FileStat], conns:[ConnStat], syscalls:[SysStat], children:[ProcKey], maps:[MapRow]|null, findings:[Finding]}
GhStatus{state:"uploading"|"starting"|"running"|"finished"|"failed", run_id, message} | GhReport{report:GhReport}
ActResult{ok:bool, message} | Error{code, message} | Pong{n}
```
Core types:
```
ProcKey{tgid:u32, start:u64}
ProcRow{key, parent:ProcKey|null, exe:BStr, comm:BStr, uid:u32, kthread:bool, cpu_pct:f32, rss:u64, threads:u32,
        io_r:u64, io_w:u64, n_open:u64, n_conn:u64, n_exec:u64, n_child:u64, n_sys:u64,
        score:u8, tree_score:u8, top_rule:string|null, exited_ts:u64|null, followed:bool, ev_dropped:u64}
Loss{ringbuf:u64, budget:u64, scratch:u64, since_ts_ns:u64}
Event{id:u64, ts_ns:u64, proc:ProcKey, tid:u32, uid:u32, kind:<one of>
   Exec{exe:BStr, argv:BStr, argv_trunc:bool, fileless:bool, dev:u64, ino:u64}
   Fork{child:ProcKey} | Exit{}
   Open{path:BStr, dev, ino, read:bool, write:bool, create:bool, trunc:bool, path_trunc:bool}
   Rename{old:BStr, new:BStr, dev, ino, approx:bool} | Unlink{path:BStr, dev, ino, approx:bool}
   Connect{family:"inet"|"inet6"|"unix"|"other", addr:string, port:u16, sock:"stream"|"dgram"|"other"}
   Listen{addr:string, port:u16}}
Finding{id:u64, rule:string, title, attack:string|null, proc:ProcKey, exe:BStr, ts_ns, weight:f32, confidence:f32,
        summary:string, why:[string], benign:[string], evidence:[u64 event ids], evidence_events:[Event] (<=10)}
```
Versioning: `proto` is an integer. Additive fields do not bump it. Any removal, rename or meaning change bumps it; the daemon rejects a mismatched `Hello` with `Error{code:"proto_mismatch"}`. Golden JSON files in `fixtures/proto/v1/` pin the encoding; changing one requires bumping `proto`.

Recording format (`--record`, `sysscope replay`, GUI `--replay`): JSONL, first line `{"sysscope_record":1,...Welcome fields}`, then one daemon->client message per line, plus `{"t":"RawEvent",...}` lines when recording core inputs. Two flavours: `*.events.jsonl` (inputs to core: events + proc samples, used for detector replay) and `*.frames.jsonl` (outputs to clients, used for GUI replay).

### 4.6 Retention limits (`limits.rs`)

Live processes tracked 8192; exited processes kept 10 min, max 2048; per-process recent events 2000; global event ring 100 000; per-process series 3600 points at 1 Hz; findings kept 5000; per-process distinct files 5000 and connections 2000 (then counted as "other"). Daemon RSS budget 300 MiB (systemd `MemoryMax=512M`).

### 4.7 Socket and access control

- Installed: `/run/sysscope/sysscope.sock`, `0660 root:sysscope`. Dev mode (`--dev`): `/run/sysscope-dev/sysscope.sock`, group = `SUDO_GID`.
- On accept: read `SO_PEERCRED`; log uid/pid. `Act` requires peer uid 0 or membership of group `sysscope-act`, and `--enable-act`.
- Client frames are untrusted: size-limited, parsed with serde into strict enums, never used to build paths or shell commands.

## 5. Detection engine

### 5.1 Model

A rule is a Rust function registered in `sysscope-core::rules` with signature conceptually `fn(&State, trigger) -> Vec<Finding>`, triggered either per event or per 1 s tick. Rules read thresholds and path classes from `Rules` (parsed from `rules.toml`, embedded default + `/etc/sysscope/rules.toml` override). Each rule has: id, title, ATT&CK technique id (where one fits), weight `w` in (0,1], and computes a confidence `c` in (0,1] per finding.

De-duplication: one active finding per (rule, process, subject) where subject is the file class, destination or window; repeats update evidence and timestamp instead of creating new findings.

### 5.2 Score

For process P at time `now`, for each rule r with findings on P:
`s_r = w_r * max over findings f of ( c_f * 0.5^((now - t_f) / 600 s) )`
`score(P) = round(100 * (1 - product over r of (1 - s_r)))`
`tree_score(P)` = same formula over P and all descendants still in state.
Bands: 0 none, 1-29 low, 30-59 suspicious, 60-100 high. Alerts are sent when a process first enters "suspicious" and first enters "high".
Worked example (must be a unit test): R002 (w 0.4, c 1.0) + R001 (w 0.6, c 0.9) -> 1 - (0.6 * 0.46) = 0.724 -> 72.

### 5.3 Allowlist

Entries `{rule, exe, subject, reason}` in the embedded defaults and `/etc/sysscope/allow.toml`. An entry matches only if the process exe path equals `exe` (glob allowed on the last component only) AND the exe file is owned by uid 0 and neither it nor its directory is group/world-writable (checked by the daemon at exec time and cached with the Exec event). A match suppresses the finding and increments a per-rule "allowlisted" counter visible in Detail. Ship defaults for obvious cases (sshd/ssh/ssh-agent/git for SSH keys; sudo/su/login/sshd/passwd/polkit for shadow; the browser binaries for their own profile; cron/systemd/package managers for persistence paths). Every finding's explanation includes the exact allowlist entry text that would suppress it.

### 5.4 Rules

| Id | Title | Trigger and default thresholds | w | c | ATT&CK |
|---|---|---|---|---|---|
| R001 | Credential file read | Open(read) of a path in class `credentials`: `~/.ssh/id_*` (not `.pub`), `/etc/shadow`, `/etc/gshadow`, `~/.aws/credentials`, `~/.config/gcloud/*`, `~/.kube/config`, `~/.netrc`, `~/.gnupg/private-keys*`, `~/.docker/config.json`, browser `Login Data`/`logins.json`/`key4.db`/`cookies.sqlite`, `~/.local/share/keyrings/*`, `*.kdbx`, wallet files | 0.6 | 0.9 if exe is outside root-owned system dirs, else 0.5 | T1552 |
| R002 | Execution from a writable temp location | Exec with exe under `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user/*`, or any dir that is world-writable | 0.4 | 1.0 | T1204 |
| R003 | Fileless execution | Exec with FILELESS flag (exe inode has nlink 0, e.g. memfd) | 0.7 | 0.9 | T1620 |
| R004 | Persistence location written | Open(write/create/trunc) or Rename-into class `persistence`: `/etc/cron*`, `/var/spool/cron/*`, `/etc/systemd/system/*`, `/usr/lib/systemd/system/*`, `~/.config/systemd/user/*`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.config/autostart/*`, `/etc/profile.d/*`, `/etc/ld.so.preload`, `/etc/rc.local`, `~/.ssh/authorized_keys`, `/etc/udev/rules.d/*`, `/etc/init.d/*` | 0.6 | 0.8; 1.0 for `ld.so.preload` and `authorized_keys` | T1053/T1543/T1546 |
| R005 | Mass file rewrite (ransomware-like) | Within a 10 s window for one process tree, under user-data dirs (`/home/*`, excluding `.cache`, `.git`, `node_modules`, `target`, `__pycache__`, and the process's own cwd build dirs): (a) >= 20 distinct inodes each write-opened then renamed, or unlinked after a new sibling was created; c = 0.9 if >= 80% of renames change to one common new extension, else 0.5. (b) >= 30 distinct pre-existing inodes opened write+trunc across >= 3 directories; c = 0.4 | 0.8 | per variant | T1486 |
| R006 | Regular-interval connections (beaconing) | Same process exe -> same non-loopback (addr, port): >= 6 connects spanning >= 60 s, mean interval 5 s..3600 s, coefficient of variation <= 0.15 | 0.5 | 0.6; 0.8 if the address is public | T1071 |
| R007 | Connection fan-out (scanning) | Within 10 s: >= 100 distinct (addr, port), or >= 25 distinct ports on one addr, or >= 50 distinct addrs on one port | 0.5 | 0.7 | T1046 |
| R008 | Event flood | Kernel budget dropped events for the process in 3 consecutive seconds | 0.3 | 0.6 | T1562 |
| R012 | Decoy touched | Any Open/Rename/Unlink whose (dev,ino) is in the decoy set (Glasshouse manifest, or host canaries listed in `/etc/sysscope/canaries.toml`) | 0.9 | 1.0 for write/rename/unlink, 0.8 for read | - |
| R009 | Shell spawned by an unusual parent (WP28) | Exec of a shell/interpreter whose parent exe is in class `no_shell_parents` (document viewers, browsers, web servers, mail clients) | 0.5 | 0.6 | T1059 |
| R011 | Process injection attempt (WP28) | `fentry/security_ptrace_access_check` with ATTACH mode on a process outside the caller's own tree, caller not a known debugger | 0.6 | 0.7 | T1055 |
| R100 | Unlike itself (WP28, experimental, off by default) | Jensen-Shannon divergence between the last 5 min behaviour vector of an exe (syscall mix top 32, file dir classes, distinct destinations, child count) and its stored baseline exceeds the baseline's own 99th percentile; baseline needs >= 6 h and >= 20 runs | 0.3 | 0.5 | - |

### 5.5 Honest limits (put this list, reworded for users, in docs/LIMITATIONS.md and the README)

Not detectable from this telemetry: file content (no entropy on the host, so encryption is indistinguishable from compression or an editor's save); writes through `mmap`; DNS names and any payload (only addresses and ports); unconnected UDP sends; inbound accepted connections; anything a process does through fds opened before tracing started or inherited; work delegated to another process (cron, systemd-run, D-Bus services, a compromised allowlisted binary); kernel-level or rootkit activity; anything by a root attacker who stops the daemon or detaches the programs. Paths are best-effort for rename/unlink. Short-lived processes may lack /proc data. Rules are heuristics: expect both false positives (backup tools, IDEs, package managers, scanners used legitimately) and false negatives (slow, low-volume, or allowlisted-binary abuse).

### 5.6 Explanation format (identical in CLI, GUI and export)

```
[HIGH 72] /tmp/x (pid 4312, started 12:01:03, parent /usr/bin/bash pid 4100, uid 1000)
R001 Credential file read - ATT&CK T1552 - weight 0.6, confidence 0.9
What happened: opened /home/u/.ssh/id_ed25519 for reading at 12:01:05.
Why it is flagged:
  - this file is a private SSH key
  - the program is not on the allowlist for SSH keys
  - the program runs from a world-writable directory
Could be harmless if: you ran a backup or key-management tool yourself.
Evidence (2 events): #18812 Open ..., #18815 Open ...
To silence: add to /etc/sysscope/allow.toml -> { rule = "R001", exe = "/tmp/x", subject = "ssh_keys", reason = "..." }
```
Rule texts (`title`, `why`, `benign`) live in `rules.toml` so wording can change without code.

### 5.7 Evaluation without real malware

1. Replay fixtures: for each rule at least 3 positive, 3 negative and 2 boundary `*.events.jsonl` files with an `expected.json` (exact rule ids, subjects, scores). 
2. Simulators (`testkit/sim/`): one harmless script per rule that performs the behaviour only inside a directory it is given and only if that directory contains the marker file `.sysscope-sim-ok`; network simulators talk only to 127.0.0.0/8 and a local listener they start. End-to-end test: run simulator, assert the finding appears with correct evidence.
3. Benign corpus: scripted workloads recorded on the host and in VMs - `apt-get update` + install/remove a small package, `git clone` + build of a small C project, `cargo build` of this repo, `tar`/`zip` of a tree, `rsync` of a tree, an editor-style save loop, `pip install` into a venv, `ssh localhost true`, `curl` a few local URLs, 30 minutes of idle desktop. Pass threshold: zero findings at "high", and at most 2 at "suspicious" per recorded hour, each then either allowlisted with a reason or documented as an accepted false positive.
4. Optional (inside a VM only, never the host): Atomic Red Team Linux atomics for the mapped techniques `[VERIFY availability and licence; skip if it requires anything outside the pre-authorised list]`.

## 6. Glasshouse sandbox

### 6.1 Run flow

1. Client uploads the sample bytes (<= 256 MiB) and args. Daemon writes them to `/var/lib/sysscope/glasshouse/<run_id>/sample` (dir `0750 root:sysscope-box`, a dedicated tmpfs of 512 MiB mounted `nodev,nosuid` at the run dir by the helper). The helper is a separate root process started by the daemon through `systemd-run --wait --pipe` as its own transient unit, so the daemon's capability bounding set stays minimal `[VERIFY; fallback: spawn directly and add only the capabilities the helper needs, recorded in THREAT_MODEL.md]`. Helper and daemon talk over the helper's stdin/stdout with one JSON object per line (`{"need":"follow_cgroup","id":...}`, `{"need":"decoys","inodes":[...]}`, `{"status":...}`, `{"report":...}`); the daemon treats helper output with the same size limits and strict parsing as client frames.
2. Daemon spawns `sysscope-glasshouse prepare <run_id>`: generates decoys into `<run>/home`, writes `<run>/manifest.json` (path, dev, ino, size, sha256, entropy, mode), builds a synthetic `<run>/etc`, compiles the seccomp filter to `<run>/seccomp.bpf`.
3. Helper starts a transient service with `systemd-run` as user `sysscope-box` (system user, no home, no shell, no supplementary groups) running `sysscope-glasshouse stage2`, with properties in 6.2. Stage2 blocks reading a FIFO.
4. Helper resolves the unit's cgroup path, obtains its cgroup id `[VERIFY: cgroup v2 id equals the inode number of the cgroup directory; confirm against bpf_get_current_cgroup_id from a test program]`, asks the daemon to insert it into `followed_cgroup` and to add manifest inodes to the decoy set, then writes to the FIFO.
5. Stage2 `exec`s `bwrap` with the arguments in 6.2, which runs the sample.
6. End: sample exits, or timeout (default 60 s, max 600 s) -> `systemctl kill --signal=SIGKILL` then stop the unit. Helper waits for the cgroup to be empty.
7. Helper drops privileges to `sysscope-box` for the diff (never root), runs the differ, emits `GhReport`, then root unmounts and deletes the run dir. Reports are kept as JSON under `/var/lib/sysscope/reports/` (0640 root:sysscope).

### 6.2 Isolation specification

systemd transient unit properties `[VERIFY each exists in the installed systemd; man systemd.exec]`: `User=sysscope-box`, `NoNewPrivileges=yes`, `MemoryMax=1G`, `MemorySwapMax=0`, `TasksMax=256`, `CPUQuota=100%`, `LimitCORE=0`, `LimitFSIZE=268435456`, `LimitNOFILE=1024`, `RuntimeMaxSec=<timeout+5>`, `KillMode=control-group`, `StandardInput=null`, `StandardOutput=file:<run>/stdout` and `StandardError=file:<run>/stderr` (capped by LimitFSIZE), `OOMPolicy=kill`, `CollectMode=inactive-or-failed`.

bwrap arguments `[VERIFY names against man bwrap]`: `--unshare-all` (user, pid, net, ipc, uts, cgroup), `--die-with-parent`, `--new-session`, `--cap-drop ALL`, `--hostname glasshouse`, `--clearenv` then a minimal env (`PATH`, `HOME=/home/victim`, `USER=victim`, `LANG=C.UTF-8`), `--uid 1000 --gid 1000`, `--ro-bind /usr /usr`, `--symlink usr/bin /bin` (and `/sbin`, `/lib`, `/lib64` as on the host), `--ro-bind <run>/etc /etc`, `--bind <run>/home /home/victim`, `--ro-bind <run>/sample /sample/<name>`, `--proc /proc`, `--dev /dev`, `--tmpfs /tmp`, `--tmpfs /run`, `--tmpfs /var`, `--chdir /home/victim`, `--seccomp <fd>`. No `/sys`, no X11/Wayland sockets, no D-Bus, no host home, no `/var/lib/sysscope`.

Synthetic `/etc`: copies of `ld.so.cache`, `ld.so.conf`, `ld.so.conf.d/`, `alternatives/`, `ssl/certs/`, `nsswitch.conf`, `localtime`; generated `passwd`, `group`, `hostname`, `hosts`, `resolv.conf` (empty), and decoy `shadow` (fake hashes, in the manifest). Nothing else from the host `/etc`.

Seccomp (build with the `seccompiler` crate `[VERIFY API]`; fall back to `libseccomp` bindings): default allow, with these returning EPERM unless noted: `bpf`, `perf_event_open`, `ptrace`, `process_vm_readv`, `process_vm_writev`, `userfaultfd`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `keyctl`, `add_key`, `request_key`, `mount`, `umount2`, `pivot_root`, `chroot`, `move_mount`, `open_tree`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `unshare`, `setns`, `clone` when flags include any `CLONE_NEW*`, `clone3` -> ENOSYS (so libc falls back to `clone`), `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `open_by_handle_at`, `name_to_handle_at`, `swapon`, `swapoff`, `reboot`, `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`, `acct`, `quotactl`, `personality` (except 0 and 0xffffffff), `iopl`, `ioperm`, `modify_ldt`, `vhangup`, `syslog`, `lookup_dcookie`, `kcmp`, `landlock_*` is allowed, `seccomp` is allowed (can only tighten). Reject non-native architectures (x32, i386) with KILL_PROCESS.

Decoys (all fake, generated per run with random content; nothing copied from the host): `~/.ssh/id_ed25519` + `.pub` (fresh throwaway key from `ssh-keygen`), `~/.ssh/known_hosts`, `~/.aws/credentials` (AWS's documented example key id), `~/.config/google-chrome/Default/Login Data` and `~/.mozilla/firefox/x.default/logins.json` + `key4.db` (random bytes with correct file names), `~/.bash_history`, `~/passwords.txt`, `~/wallet.dat`, `~/Documents/*.docx|.xlsx|.pdf|.txt` (20 files), `~/Pictures/*.jpg` (10 files), `~/.gnupg/private-keys-v1.d/x.key`, `/etc/shadow`.

### 6.3 Differ and report

Runs as `sysscope-box`, opens the run dir with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` semantics `[VERIFY crate support; otherwise O_NOFOLLOW on every component]`, `lstat` only, regular files only (others are listed by type, never opened), max 20 000 entries, max 64 MiB hashed per file, total time cap 30 s. Per decoy status: `untouched`, `read` (from trace), `modified` (sha256 differs; report size and Shannon entropy before -> after), `renamed` (same ino, new name), `deleted`, plus `created` for new files (name, size, entropy, first 256 bytes escaped only if they are printable text). Report also includes the event timeline, connection attempts, child processes, findings, loss counters, and the limitation text in 6.4. Wording for entropy: "entropy rose from 4.1 to 7.9 bits/byte, consistent with encryption or compression".

### 6.4 What Glasshouse does NOT guarantee (verbatim in the GUI Glasshouse tab, the report footer, README and docs)

"Glasshouse is a behaviour-demonstration sandbox, not a malware containment system. The program you run shares this computer's kernel. A kernel or sandbox vulnerability, a CPU side-channel, or a mistake in configuration could let it read your data or take over your account or the machine. Glasshouse does not hide that it is a sandbox, so a program may behave differently inside it. Run only programs you would accept losing this machine to, such as your own test scripts. For real or suspected malware use a dedicated virtual machine or a separate computer with no network, following docs/REAL_SAMPLES.md."

### 6.5 Threats and mitigations (the adversarial suite in WP25 has one probe per row)

| Attack | Mitigation | Residual |
|---|---|---|
| Kernel exploit via syscalls | seccomp blocks high-risk syscalls; no user namespaces inside; unprivileged uid | Not mitigated in general -> VM for real samples |
| Read host files | mount namespace with only /usr ro, synthetic /etc, decoy home | /usr contents and /proc/{cpuinfo,meminfo,version} visible (host fingerprint) |
| See or signal host processes | pid namespace; fresh /proc | none known |
| Network exfiltration / lateral movement | net namespace, loopback only | none; attempts are logged |
| Reach X11, D-Bus, tracer socket, abstract Unix sockets | not bound; /run is tmpfs; net namespace isolates abstract sockets | none known |
| Privilege gain via setuid binaries in /usr | NoNewPrivileges, cap-drop ALL | none known |
| Nested user namespace to regain capabilities | seccomp on unshare/clone flags/clone3/setns | relies on the filter being correct: tested |
| TIOCSTI / terminal injection | `--new-session`, stdio is files, no tty | none |
| Fork bomb, memory bomb, CPU hog | TasksMax, MemoryMax + no swap, CPUQuota, wall-clock timeout, cgroup kill | brief load spike |
| Disk fill | run dir is a 512 MiB tmpfs; /tmp,/var,/run tmpfs count against MemoryMax; LimitFSIZE | none |
| Blind or flood the tracer | per-tgid kernel budget; drops counted and reported; R008 | events beyond budget are lost (counted) |
| Tamper with the tracer | no bpf/perf/ptrace syscalls; cannot see or reach the daemon | none known for an unprivileged, contained process |
| Core dump handled by a host root helper | LimitCORE=0 `[VERIFY: with a piped core_pattern a limit of 0 suppresses the handler; test in VM]` | - |
| Malicious files left for the host to parse (symlinks, FIFOs, huge trees, hostile names) | differ runs unprivileged, no symlink following, regular files only, caps, escaping (I10) | none known |
| Persisting after the run | cgroup kill, tmpfs unmounted and removed, host never executes anything from the run dir | none |
| Leaked inherited file descriptors | stage2 closes all fds >= 3 before exec (`close_range`); test asserts `/proc/self/fd` in the box has only 0-2 plus bwrap's | - |
| Detecting the sandbox and staying quiet | none | accepted; documented |
| Side channels (Spectre-class, timing) | none | accepted; documented |

### 6.6 Real samples (docs/REAL_SAMPLES.md + `vm/detonate.sh`), WP26

Never on the host. Protocol the script implements and the doc explains step by step:
1. Owner places the sample, still inside a password-protected archive, in `~/sysscope-quarantine/` (0700). The owner obtains samples himself; neither the docs nor Opus link to or fetch any.
2. `vm/detonate.sh <archive> <password> [timeout]` builds a read-only ISO containing the archive, boots the detonation guest (Debian cloud image with SysScope preinstalled, built once by `vm/build-detonation-image.sh`) with `-snapshot` (all disk writes discarded), `-nic none` (no network device at all), no shared folders, no clipboard, no USB passthrough, 2 vCPU, 2 GiB RAM, a second serial port connected to a host file.
3. Inside the guest an autorun unit extracts the sample and runs it in Glasshouse (sandbox inside the VM), then writes the JSON report to the second serial port and powers off.
4. Host kills QEMU at timeout + 60 s regardless. Host reads the serial file as untrusted text: size cap 64 MiB, parsed with the same strict serde types, displayed with escaping.
5. The doc states the remaining risk plainly: hypervisor escapes exist though they are rare; keep the host patched; never add a network device; never mount the guest disk on the host; never copy anything out of the guest except through the serial report.
The script refuses to run if QEMU would start without KVM, if any `-nic`/`-netdev` other than `none` is present in its own command line, or if a VirtualBox VM is running.

## 7. Work packages

Format per WP: Goal / Inputs / Contract / Invariants / Pitfalls / Verify / Done. "Done" always additionally requires: `make lint` and `make test` green, PROGRESS.md updated, committed and pushed.

### Milestone M0 - Foundations

**WP00 Preflight.** Goal: prove the environment and record it. Do: check `sudo -n true`; kernel, BTF, `/dev/kvm` access, `VBoxManage list runningvms` (if present), cgroup v2 (`stat -fc %T /sys/fs/cgroup` = `cgroup2fs`), systemd version, free disk/RAM, `sysctl kernel.unprivileged_userns_clone kernel.perf_event_paranoid kernel.unprivileged_bpf_disabled`; run `make setup` equivalent by hand (apt packages from section 2, rustup). Contract: `docs/ENV.md` with every value and tool version. Pitfalls: Kali may name the bpftool package differently (`bpftool` vs `linux-tools`) - search the repo index; do not add repos. Verify: `rustc --version && clang --version && bpftool version && qemu-system-x86_64 --version && bwrap --version` all succeed; a 5-line test BPF program from the libbpf-rs examples compiles (not loaded yet). Done: ENV.md committed; any E1-E5 condition escalated.

**WP01 Scaffold.** Goal: empty workspace that builds, lints and tests, with CI. Contract: crates from 4.1 as stubs; `Makefile` with exactly the targets in SKILL.md section 6; `rust-toolchain.toml`; clippy config per conventions; `.github/workflows/ci.yml` running `make lint test` on `ubuntu-24.04` (keep under 10 min; private-repo minutes are limited); `gh repo create sysscope --private` and push; LICENSE (MIT), `.gitignore`, `deny.toml`; a CI script `scripts/check-integrity.sh` that fails if any test has `#[ignore]`, or if a threshold constant in `limits.rs`, `rules.toml` defaults or the bench thresholds changed in a commit range without a matching line under "Deviations from the plan" in PROGRESS.md. Pitfalls: never `sudo cargo`. Verify: `make build && make lint && make test`; `gh run watch` shows CI green. Done: green CI on the private repo.

**WP02 Protocol crate.** Goal: implement 4.5 exactly. Contract: all types with serde; `read_frame`/`write_frame` over `std::io::Read`/`Write` with the size limits; `BStr` escaping; golden fixtures in `fixtures/proto/v1/*.json` (one per message type). Invariants: I10; decoding never panics on any input. Pitfalls: serde `deny_unknown_fields` must NOT be used (forward compatibility); f32 NaN is not valid JSON - clamp. Verify: `cargo test -p sysscope-proto` including proptest round-trips (`BStr` over arbitrary bytes; every message type), golden-file equality, frame decoder on truncated/oversized/garbage input returns `Err` without panic (10 000 proptest cases). Done: tests green; fixtures committed.

**WP03 VM harness.** Goal: one command boots a clean guest, copies the build in, runs a command as root, returns its exit code. Contract: `vm/up.sh <distro>`, `vm/run.sh <distro> <cmd>`, `vm/down.sh`; images cached in `~/.cache/sysscope-vm` with SHA256 verified against the distro's published checksums; cloud-init seed ISO creating a user with an ephemeral SSH key; user-mode networking with one forwarded SSH port bound to 127.0.0.1; `-snapshot` by default; KVM required. Distros: `debian12`, `ubuntu2204`, `ubuntu2404`, `fedora` (current), `arch`. Guests build nothing: copy release binaries built on the host (WP30 later switches to packages). Pitfalls: VirtualBox/KVM conflict `[VERIFY: on kernels >= 6.12 KVM may hold VT-x from module load and the two hypervisors cannot run VMs at once]` - if QEMU fails with a VMX/KVM error, escalate E2, do not unload modules. Verify: `vm/run.sh debian12 'uname -r && test -f /sys/kernel/btf/vmlinux && echo OK'` prints OK for each distro. Done: all five boot; any that cannot is recorded in UNVERIFIED.md and escalated only if debian12 fails.

### Milestone M1 - Collector core

**WP04 BPF skeleton + lifecycle.** Goal: daemon loads CO-RE programs for exec/fork/exit and prints decoded events as JSONL (`sysscoped --dev --dump`). Contract: `bpf/sysscope.h` ABI (4.3), `vmlinux.h` generated once with `bpftool btf dump ... format c` and committed under `bpf/vmlinux/x86_64/` with the kernel version noted; `build.rs` using libbpf-cargo's skeleton builder; `abi.rs` converting `&[u8]` to typed events with length checks (only unsafe in the project); ring buffer + `drops` map + `ignored_tgid` containing the daemon. Invariants: I2, I3, I4, I14; startup asserts init pid namespace and BTF presence with clear errors. Pitfalls: confirm tp_btf argument order for each tracepoint from BTF (`btf_trace_sched_process_exec` etc.); `sched_process_exit` fires per thread - decide and test the "process gone" signal: emit EXIT when `pid == tgid` and additionally let the /proc sampler confirm disappearance (a leader can exit before its threads) `[VERIFY with a test program whose main thread exits first]`; argv read uses `bpf_probe_read_user` from `mm->arg_start` with the cap; libbpf-rs static/vendored feature names `[VERIFY in the installed version]`. Verify: load in debian12 VM first, then host: run `/bin/true` 100 times from a known parent; dump shows exactly 100 EXEC, 100 FORK, 100 EXIT for that parent's children with correct exe path; `dmesg` clean. Done: verify passes on host and debian12.

**WP05 Ground-truth workload + harness.** Goal: `testkit/wl` (C, no libc buffering surprises: direct syscalls via `syscall()`) performs exactly N of each action and prints a JSON manifest of what it did. Actions: `exec N`, `fork N`, `open-read N`, `open-write N`, `rename N`, `unlink N`, `connect-tcp N` (to a local listener it starts), `connect-fail N`, `listen N`, `threads N`, `syscalls NR N`, `flood N`, `longpath`, `badname` (non-UTF-8, newline, escape sequences), `memfd-exec`, `leader-exits-first`. Contract: `sysscope-itest` helper `run_wl(args) -> (manifest, observed events filtered by wl's ProcKey subtree)`. Verify: `make test-root` runs the lifecycle cases and asserts observed == manifest exactly. Done: harness reusable by later WPs; itest runs single-threaded.

**WP06 File events.** Goal: OPEN, RENAME, UNLINK per D6. Contract: 4.3 structs; flags mapped from `f_flags`/`f_mode`; `(dev,ino)` from `file->f_inode` (`i_sb->s_dev`, `i_ino`); kernel threads skipped. Invariants: I5; truncation flagged, never silent. Pitfalls: `bpf_d_path` legality at this hook `[VERIFY; fallback if rejected: fentry on another function in the kernel's d_path allowlist such as `vfs_open`/`dentry_open`/`file_open`-adjacent - check `btf_allowlist_d_path` in the kernel source for the minimum supported version - and if none works, dentry walk as for rename]`; `security_inode_rename` prototype across matrix kernels `[VERIFY]`; `s_dev` encoding differs from `st_dev` in userspace (kernel `dev_t` vs `makedev`) - convert once in the daemon and test equality with `stat`; opens of directories and of `/proc` files are frequent - keep them (rules ignore them) but they consume budget. Verify: itest with wl: 1000 open-read, 500 open-write, 200 rename, 200 unlink -> exact counts, `(dev,ino)` equal to `stat`, paths equal for opens; `longpath` sets PATH_TRUNCATED; `badname` round-trips through `BStr`; a relative-path open and an open through a symlink both report the resolved absolute path; an `io_uring` open is observed (small C test; if liburing is absent use raw syscalls) `[VERIFY]`. Done: passes on host + debian12 + ubuntu2204 (5.15).

**WP07 Network events.** Goal: CONNECT and LISTEN per D7. Contract: families inet/inet6/unix/other; v4-mapped v6 addresses normalised to v4; unix socket paths as BStr in `addr` (abstract sockets shown with leading `@`). Pitfalls: the sockaddr parameter type changed name in recent kernels `[VERIFY the prototype of security_socket_connect on the host (6.19) and on 5.15; read the family and bytes with bounded `bpf_probe_read_kernel` using `addrlen`, never trust `addrlen` > 128]`; non-blocking connects are still observed at this hook (good); port is network byte order. Verify: wl `connect-tcp 300` (v4 and v6), `connect-fail 50`, `listen 10`, plus one UDP `connect`: exact counts, addresses and ports. Done: host + debian12 + ubuntu2204.

**WP08 Syscall stats.** Goal: per-process syscall counts system-wide; latency for followed. Contract: maps `sys_count`, `sys_lat`, `sys_start`; daemon reads and resets deltas every 1 s (batch lookup if available `[VERIFY]`, else iterate), sums per-CPU values; syscall names from a table generated at build time from the kernel headers' `unistd_64.h`. Config `syscalls = "count" | "off"` in `/etc/sysscope/sysscoped.toml` (default count). Pitfalls: `raw_tp/sys_enter` args are `(struct pt_regs *, long id)`; ids can be -1; `sys_exit` for `execve` and `exit` do not pair - LRU handles orphans; do not emit events. Verify: wl `syscalls getppid 100000` -> count within +-0.1% (exact unless LRU eviction; assert exact when the map is not full); followed latency mean for `nanosleep(1ms)` x 200 is between 1.0 and 3.0 ms. Done: host + debian12.

**WP09 Follow mode + budgets.** Goal: kernel-enforced follow (D9) and per-tgid budgets (D10). Contract: daemon API `follow(root)`: insert root, then scan /proc for descendants repeatedly until two consecutive scans add nothing, then set `cfg.mode = 1`; `unfollow()` sets mode 0 and clears the map. Fork inheritance in the fork program for both thread-group creation and `vfork`/`clone` variants. Budget token bucket as specified in 4.3. Invariants: I3; in follow mode an unfollowed process produces zero events. Pitfalls: inheritance must key on the parent's tgid, not the forking thread's pid; a daemonising double-fork stays followed because inheritance happens at fork time; token refill arithmetic must not overflow and must tolerate concurrent CPUs (lost updates are acceptable, negative tokens are not). Verify: (a) follow a shell, spawn 3 generations including a double-fork daemon; all followed; an unrelated wl run yields 0 events; (b) wl `flood 200000` opens: `received + budget_dropped + ringbuf_dropped == 200000` exactly, and a concurrent second wl doing 1000 opens loses 0; (c) with ring buffer forced to 64 KiB the same identity holds. Done: host + debian12.

**WP10 /proc sampler + identity.** Goal: 1 Hz samples of CPU%, RSS, threads, IO totals for all processes; initial process table at startup; ProcKey reconciliation. Contract: use the `procfs` crate `[VERIFY it exposes stat starttime, statm/status, io, and handles races]`; processes that vanish mid-read are skipped without error; CPU% = delta(utime+stime)/delta(wall) x 100, can exceed 100 on multi-core; on-demand `/proc/<pid>/maps` for Detail (cap 5000 rows). Pitfalls: 4.4 start_ticks equality; `/proc/<pid>/io` needs privilege; exe for pre-existing processes via `readlink /proc/<pid>/exe` (may end in " (deleted)"). Verify: test compares BPF-derived ProcKey for 200 freshly spawned processes with /proc-derived ProcKey: 200/200 equal; a busy-loop child shows 90-110% CPU; a child that allocates and touches 200 MiB shows RSS within 10%. Done: host + debian12.

**WP11 Core state.** Goal: `sysscope-core::State` implementing process table, tree, counters, per-process recent events, series, files/connections summaries, retention limits (4.6), snapshot and detail builders; `replay(events.jsonl) -> outputs`. Invariants: I7, I8. Contract: `apply_event`, `apply_samples`, `tick(now_ns)`, `snapshot()`, `detail(key)`. Pitfalls: events can arrive for an unknown process (started before tracing or FORK dropped) - create a placeholder and fill from the next sample; parent may exit before child - keep the original parent key, mark orphan; EXEC replaces exe in place (same ProcKey). Verify: unit tests for each limit (insert limit+1000, assert cap and counters); property test: for any random valid event sequence, tree has no cycles, every child's parent key exists or is null, counters equal a naive recount; replay of `fixtures/core/basic.events.jsonl` equals golden `snapshot.json`. Done: tests green; 1 000 000-event replay stays under 300 MiB RSS and finishes in under 20 s (measured with `/usr/bin/time -v`).

**WP12 Daemon assembly.** Goal: 4.2 threads, 4.5 protocol server, 4.7 access control, `--record`, config file, graceful shutdown (SIGTERM detaches programs and removes the socket). Invariants: I1, I3, I11, I12. Pitfalls: stale socket file on restart (unlink only if no live listener); set socket mode before `listen`; SIGPIPE ignored; a slow client must not slow T3 (test it). Verify (itest): 8 clients connect, a 9th is refused; a client that never reads is disconnected within 6 s while another client's snapshot interval stays under 700 ms; malformed and oversized frames get `Error` and close without daemon crash; `strace -f -e trace=network` on the daemon for 30 s shows no socket family other than AF_UNIX/AF_NETLINK; daemon RSS after 10 min of wl churn under 300 MiB. Done: host + debian12.

**WP13 CLI.** Goal: `sysscope status | top | tree | tail [--proc] | follow <pid> | unfollow | detail <pid> | findings | export --format json|csv [--raw] | replay <file> | glasshouse run <file> [args]` (last one stubbed until WP24). Contract: output escaping (I10) including a test with terminal escape sequences in file names; export redaction ON by default (section 9.2), `--raw` prints a warning to stderr; `--json` on every subcommand for scripting; exit codes documented. Verify: itest drives the CLI against the daemon and against replay; CSV parses with Python's `csv` module; redaction test: a home path, an argv `--password=hunter2`, and a URL with credentials do not appear in default export. Done: green.

**WP14 Overhead benchmarks.** Goal: `make bench` measures and enforces. Method: each benchmark 10 runs alternating tracer off/on (`hyperfine` or a script), report median and spread, CPU governor noted, fail if spread > 10% (rerun). Thresholds (provisional targets set by the architect; if missed, apply the levers below, and if still missed escalate E6 with the numbers - do not relax): macro A `cargo build` of this repo (clean) wall time +<= 5%; macro B unpack + compile of a small C project with `make -j` +<= 5%; micro open/close x 500 000 +<= 40%; micro `getppid` x 5 000 000 +<= 60% with `syscalls=count` and +<= 5% with `syscalls=off`; follow mode on an unrelated process: all benchmarks +<= 3%; daemon CPU on an idle desktop <= 3% of one core averaged over 5 min; daemon RSS <= 300 MiB. Levers, in order: move gates earlier; avoid `bpf_d_path` when over budget before reserving; per-CPU maps; smaller event structs; raise snapshot interval; batch map reads. Verify: `make bench` exits 0 and writes `docs/BENCH.md`. Done: thresholds met on host or escalated.

### Milestone M2 - Detection

**WP15 Rule engine.** Goal: 5.1-5.3 and 5.6. Contract: `Rules` from TOML (embedded default, override file, schema-validated with clear errors, bad file = daemon refuses to start); finding de-duplication; score and tree score; allowlist matching with the exe-ownership condition; explanation renderer shared by CLI/GUI/export. Invariants: I7, I9. Verify: unit test of the worked example (72); decay test (after 600 s contribution halves); allowlist test (same path but user-writable exe does not match); renderer golden test. Done: green.

**WP16 Rules R001-R004, R012.** Contract: path classes with `~` expanded per target uid's home from `/etc/passwd` (read by the daemon at start and on SIGHUP); class matching on the resolved path bytes; Rename-into counts for R004. Pitfalls: `.pub` exclusion; a process reading its own exe or libraries from `/tmp` is not R002 (R002 is about Exec); editors writing `~/.bashrc` are true positives at "suspicious" and that is acceptable - explanation says so. Verify: fixtures per 5.7(1) for each rule; simulators `sim/cred_read.py`, `sim/tmp_exec.py`, `sim/memfd_exec.py`, `sim/persist_write.py` (writes only inside its sandbox dir; for the end-to-end test the test config adds that dir to the class) produce the expected finding with correct evidence ids end to end. Done: green on host.

**WP17 Rules R005-R008.** Contract: sliding windows implemented with bounded per-process ring buffers; statistics computed incrementally; R006 state keyed by (exe, addr, port) capped at 10 000 keys LRU. Pitfalls: window logic must use event time, not wall time (replay determinism); R005 must not fire on `tar -x`, `git checkout`, `cargo build` (benign corpus), hence the pre-existing-inode and rename conditions; R006 needs jitter tolerance exactly as specified - do not "improve" it. Verify: fixtures (positive, negative, boundary: 19 vs 20 files, CV 0.14 vs 0.16, 5 vs 6 connects); simulators `sim/ransom_sim.py` (operates on generated files in its own dir, XOR "encrypts" and renames to `.locked`), `sim/beacon.py` (local listener, 8 connects at 5 s), `sim/portscan.py` (127.0.0.1 ports 20000-20200), `wl flood`. Done: green.

**WP18 False-positive evaluation.** Goal: 5.7(3). Contract: `testkit/benign/*.sh` scripted workloads; `make fp-eval` records each (host and debian12 VM), replays through the detector, writes `docs/FP_REPORT.md` with every finding. Verify: thresholds in 5.7(3) met; each remaining finding has an allowlist entry with reason or a documented acceptance. Done: report committed; recorded files added to `fixtures/benign/` as regression tests (strip with redaction first).

Then run Gate M2.

### Milestone M3 - GUI

**WP19 GUI model + transport.** Goal: `model.rs` (pure view-model: latest snapshot, selection, sort, filter text, paused flag, tree/table mode, detail cache, alerts list, connection state, loss state) and `net.rs` (reader thread -> channel; reconnect with backoff; replay source reading `*.frames.jsonl` at recorded or fixed speed). Contract: `Model::apply(msg)`, `Model::visible_rows()`, `Model::on_action(Action)`; UI code may only read `Model` and emit `Action`s. Pause freezes what is displayed but keeps receiving (bounded: while paused keep only the latest snapshot and count skipped ones). Verify: unit tests on model: sort stability, filter (substring over exe, pid, uid, rule id; case-insensitive), pause semantics, selection survives re-sort and disappears cleanly when the process is evicted, tree building from ProcRows with missing parents. Done: green.

**WP20 GUI views.** Goal: the window. Required elements (each with a stable accessibility label for tests, given in parentheses): top bar - daemon status (`status`), mode badge "System-wide" / "Following <exe> (<pid>)" (`mode`), search box (`search`), pause toggle (`pause`), export button (`export`), loss indicator showing counts when non-zero (`loss`); left - process table with columns exe, pid, user, CPU%, memory, threads, opens, connections, children, score, sortable, with a table/tree toggle (`procs`); right - detail tabs Overview (CPU and memory charts), Files, Network, Syscalls, Children, Memory maps, Findings (`detail-<tab>`); bottom - alerts list, newest first, click selects the process (`alerts`); Glasshouse tab placeholder. Each finding renders with the 5.6 format. Row colour by band with a text label as well (never colour alone). States to implement: daemon not running (shows the exact command to start it), permission denied on socket (shows the group-membership command), protocol mismatch, empty, paused, following. Refuse to start as root (I1). Debug flags: `--replay <frames.jsonl>`, `--screenshot <png> --after-frames <n>` (uses the viewport screenshot command `[VERIFY in installed eframe]`, then exits), `--select <pid>`, `--tab <name>`. Verify: `egui_kittest` tests `[VERIFY crate API; if unusable, test at Model level and rely on screenshots]` that find each label and exercise search, sort, pause, tab switch, alert click against replay data; `make gui-shot` under `xvfb-run` with software GL produces PNGs for 6 states (system-wide, detail-files, detail-findings, following, daemon-down, paused); a script asserts each PNG is non-blank (>= 500 distinct colours) and Opus opens each image and records a description confirming the required elements are visible and legible. Done: all labels found; 6 screenshots described in PROGRESS.md.

**WP21 Follow UX, loss, robustness.** Goal: follow/unfollow from the table (button and context menu) with confirmation of what following means ("other processes will not be traced while following"); loss banner; reconnect; GUI stays under 10% of one core and 300 MiB at 2 Hz with 2000 processes (replay stress fixture); no frame > 50 ms in the stress replay (measure in a test using the model + a headless frame loop). Verify: stress test; kill and restart the daemon while the GUI runs under Xvfb -> screenshot shows daemon-down then recovered. Then run Gate M3 and tag `v0.1.0` (private).

### Milestone M4 - Glasshouse

**WP22 Decoys + manifest.** Per 6.2/6.3. Verify: generator output matches manifest (re-hash); no decoy contains host data (test greps for the host username, hostname and real home path); deterministic with a seed for tests.

**WP23 Launcher.** Per 6.1/6.2, including `packaging/sysusers` for `sysscope-box`. Pitfalls: unprivileged user namespaces may be disabled (`kernel.unprivileged_userns_clone=0`) or restricted by AppArmor on Ubuntu 24.04 `[VERIFY in the ubuntu2404 VM]` - detect and report "Glasshouse unavailable: <reason>" as a daemon feature flag; never change the sysctl (E3). `systemd-run` property support differs by systemd version - probe and fail closed (if a required limit cannot be applied, do not run). Verify (debian12 VM first, then host with a harmless script): `id`, `ls /`, `cat /etc/passwd`, `ip a`, `ps aux`, `cat /proc/self/status | grep -E 'NoNewPrivs|Seccomp|Cap'`, `ls /proc/self/fd` inside the box show: uid 1000, only the specified tree, synthetic passwd, loopback only, only box processes, NoNewPrivs 1, Seccomp 2, all capability sets zero, fds 0-2 only.

**WP24 Trace integration, differ, report, UI.** Per 6.1 steps 4-7 and 6.3; `sysscope glasshouse run`; GUI Glasshouse tab: file picker (GUI reads the file and uploads bytes), args, timeout, the 6.4 text always visible, run/cancel, live decoy grid (one tile per decoy with status), timeline, final report with before/after table, export report. Demo sample `testkit/sim/fake_malware.py`: reads the SSH key and AWS file, tries to connect to 203.0.113.10:443 (TEST-NET-3, fails in the box), XOR-rewrites Documents to `.locked`, deletes Pictures, drops `README_RESTORE.txt`, tries to write `~/.bashrc`; refuses to run unless `HOME=/home/victim` and hostname is `glasshouse`. Verify: running the demo yields exactly: 2 decoys `read`, 20 `modified`+`renamed` with entropy increase, 10 `deleted`, 1 `created`, 1 connect attempt, findings R012, R001, R005, R004; every event of the run is attributed (0 events from the box cgroup missing: compare with an `strace -f -c` count of openat inside the box in a separate calibration run, within the budget-drop count). GUI screenshot of the report described.

**WP25 Adversarial suite.** `testkit/hostile/` one probe per row of 6.5, each printing `CONTAINED` or `ESCAPED:<detail>`; plus differ torture dir (symlink to `/etc/shadow`, FIFO, device-looking names, 100 000 files, 10 000-char name, ANSI/RTL/newline names, 1 GiB sparse file). Every hostile probe and the `vm-hostile` target must refuse to run unless the marker file `/etc/sysscope-test-vm` exists (created only by the VM harness's cloud-init) AND DMI reports a QEMU machine. `make vm-hostile` runs all in debian12 and ubuntu2404 guests. Verify: every probe prints CONTAINED; guest stays responsive (SSH command returns within 5 s during fork and memory bombs); differ finishes within its caps and its output contains no raw control bytes. Any ESCAPED = fix, add regression, re-run; if unfixable escalate E6. Then Gate M4 with the subagent instructed specifically to attack Glasshouse.

**WP26 Real-sample protocol.** Per 6.6. Verify with the harmless `fake_malware.py` packed in a password-protected zip: `vm/detonate.sh` produces a report file; script refuses when given `--nic user` in an override env var; QEMU command line logged in the report header contains `-nic none` and `-snapshot`. docs/REAL_SAMPLES.md written as numbered steps with a "why" line under each.

### Milestone M5 - Advanced and hardening

**WP27 Act mode (experimental).** Per D19. Contract: `Act` handling: check `--enable-act`, peer authorisation, then `pidfd_open(tgid)`, re-read start time via the pidfd's `/proc` entry and compare with ProcKey, refuse if protected, `pidfd_send_signal` (SIGSTOP/SIGCONT/SIGKILL). Protected list: pid 1, kernel threads, the daemon, any ancestor of the requesting client process, any process in the requester's session that is the display server / session manager / the GUI itself, anything owned by a uid the requester could not signal themselves unless requester is uid 0. GUI: button only when `act_enabled`; pause is one click with undo; kill requires typing the pid; an "experimental" label. Every action logged to the journal with requester uid. Verify: itest for each refusal reason; pid-reuse test (target exits, pid recycled by forcing `ns_last_pid` only inside a VM) is refused; pause/resume/kill of a wl child works.

**WP28 R009, R011, R100.** R011 adds one optional program on `security_ptrace_access_check` `[VERIFY prototype]`. R100 baseline store: `/var/lib/sysscope/baselines.json` (bounded, versioned), off by default, labelled experimental in UI. Verify: fixtures + simulators (`sim/doc_spawns_shell.py` using a renamed copy of a viewer-named binary in a test class; `sim/ptrace_attach.py` against its own child's sibling); R100 unit tests on synthetic vectors; benign corpus still within thresholds with R009/R011 on.

**WP29 Hardening.** (a) systemd unit: `CapabilityBoundingSet` minimal - determine empirically by removing one capability at a time and running `make test-root`; expected set CAP_BPF, CAP_PERFMON, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, CAP_SYS_RESOURCE, CAP_KILL (only with act), plus whatever Glasshouse helper needs `[VERIFY; record final set and why each is needed in docs/THREAT_MODEL.md]`; `NoNewPrivileges`, `ProtectSystem=strict` with explicit `ReadWritePaths`, `ProtectHome=read-only`, `PrivateTmp`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `IPAddressDeny=any`, `MemoryMax=512M`, `SystemCallArchitectures=native`, `LockPersonality`, `RestrictSUIDSGID` - keep each only if tests still pass; record `systemd-analyze security` score. (b) Fuzz targets (cargo-fuzz): frame decoder, `BStr` unescape, kernel event decoder (`abi.rs`), rules TOML loader, record-file reader, GhReport parser; 10 min each, zero crashes; corpus committed. (c) `cargo audit` and `cargo deny check` clean. (d) Threat model document: assets, trust boundaries, attacker classes (unprivileged local process, sandboxed sample, socket-group member, root), what each can and cannot do, residual risks. (e) Full adversarial subagent review of the whole codebase against SKILL.md invariants. Verify: all above recorded; Gate M5.

### Milestone M6 - Ship

**WP30 Packaging.** Per D21. Build in a container/VM of the oldest glibc target (ubuntu2204) so binaries run on all targets; libbpf linked statically `[VERIFY feature]`. Packages install: binaries to `/usr/bin`, unit (disabled), sysusers (`sysscope`, `sysscope-act` groups; `sysscope-box` user), `/etc/sysscope/*.toml` as conffiles, desktop entry + icon, docs, license. Post-install message tells the user how to enable the service and join the group, and that it monitors all users' processes. Uninstall removes the unit, socket dir and state dir; keeps `/etc/sysscope` on remove, deletes on purge. Verify: `lintian` / `rpmlint` run with no errors (warnings listed); install -> start -> `sysscope status` -> stop -> remove leaves no files (find-based check) in each matrix guest.

**WP31 Distro matrix.** `make vm-matrix`: for each distro install the package, run the root itest subset (lifecycle, files, network, follow, loss identity), one simulator per rule, Glasshouse demo (or correct "unavailable" reason), CLI export. Output `docs/COMPAT.md` table: distro, kernel, each feature pass/fail/degraded with reason. Graceful degradation rules: missing optional probe -> feature flag absent, UI shows "not available on this kernel: <reason>"; missing required probe or no BTF -> daemon exits with a one-paragraph explanation and exit code 3. Verify: table complete; no "fail" without a tracked entry in UNVERIFIED.md.

**WP32 Release automation.** `.github/workflows/release.yml` on tag `v*`: build packages, run `make test`, generate `SHA256SUMS`, attach to a DRAFT GitHub release (never published automatically - E8). `CHANGELOG.md` (Keep a Changelog style), SemVer; version single-sourced from the workspace `Cargo.toml`; `sysscope --version` prints version, git commit, protocol version. Verify: a `v0.0.0-test` tag on the private repo produces a draft release with all artifacts and checksums that verify; delete the test tag and draft afterwards.

**WP33 Docs and rename.** README (statement from section 1, 60-second quickstart, screenshots from `make gui-shot`, feature matrix, limitations, how it works diagram in text, AI-assistance disclosure: "built with heavy AI assistance; design and verification approach documented in docs/"), `SECURITY.md` (private reporting via GitHub Security Advisories, 90-day disclosure, scope, no bounty), `docs/PRIVACY.md`, `docs/LIMITATIONS.md`, `docs/THREAT_MODEL.md`, `docs/REAL_SAMPLES.md`, `docs/DEMO.md` (section 8.3), `docs/ARCHITECTURE.md` (derived from section 4, updated to match the code), man pages optional. `scripts/rename.sh <newname>` renames crates, binaries, unit, groups, paths, socket, docs; a CI test runs it into a temp copy and builds. Verify: rename test green; every command in README executed in a clean debian12 guest from a script extracted from the README code blocks.

**WP34 Final audit.** Run `make gate` + `make vm-matrix` + `make vm-hostile` + `make fuzz`; fresh-subagent review of the entire repo; reconcile `docs/VERIFIED.md` (every `[VERIFY]` in this plan has an entry) and `docs/UNVERIFIED.md`; write `LAUNCH_READINESS.md` for the owner: what works, measured numbers, known limitations, open risks, the launch checklist with each item ticked or explained, and a list of things only a human can check (real-GPU rendering, feel of the UI, the demo recording, the name). Then stop and report (E8/E12 apply to everything after this).

## 8. Shipping

### 8.1 Ship checklist (WP34 fills this in)

- [ ] All gates passed; no ignored tests; fuzz corpora committed.
- [ ] `docs/COMPAT.md` shows every release distro at pass/degraded with reasons.
- [ ] Overhead numbers in README match `docs/BENCH.md`.
- [ ] No string anywhere claims protection, antivirus capability, or sandbox safety (grep test for: "protects", "blocks malware", "safe to run", "secure sandbox", "antivirus").
- [ ] The 6.4 text is present in GUI, report, README, REAL_SAMPLES.md (test).
- [ ] Service disabled by default; uninstall is clean.
- [ ] Zero network connections (test in WP12) and unit restrictions in place.
- [ ] Export redaction on by default (test).
- [ ] `cargo audit` / `cargo deny` clean; licenses of all dependencies compatible with MIT distribution (deny.toml allowlist); vmlinux.h provenance noted.
- [ ] SECURITY.md, PRIVACY.md, LIMITATIONS.md, THREAT_MODEL.md present.
- [ ] Name decided by the owner and rename script run (owner).
- [ ] Demo recorded by the owner on real hardware (owner).

### 8.2 What would be embarrassing on launch day (each has a test or checklist item)

Daemon fails to load on a popular distro (matrix). A verifier error dumped raw at the user (startup error mapping test). The tool flags itself or common tools constantly (benign corpus). Noticeable slowdown (bench). "Root daemon that phones home" suspicion (no-network test, stated in README). Overclaiming detection or sandbox safety (grep test). A reviewer finds a trivial sandbox escape (WP25, and the README invites reports). Install script that pipes curl to sudo (we ship packages only). Screenshots that do not match the build (generated by `make gui-shot`). The owner unable to answer design questions (LEARNING_PATH.md, ARCHITECTURE.md). Name collision (owner check before going public).

### 8.3 Demo script (docs/DEMO.md; 60 seconds)

0-10 s: GUI open, system-wide table updating, sort by connections. 10-25 s: click a browser, show files/network/syscalls tabs, press Follow. 25-40 s: run `sim/cred_read.py` + `sim/beacon.py` from a terminal; alert appears; open the finding and show the evidence lines. 40-60 s: Glasshouse tab, run `fake_malware.py`, decoy tiles change live, open the before/after report. Recording: owner records on the real desktop at 1080p; keep the 6.4 text visible in frame. Opus prepares `scripts/demo.sh` that stages everything so the recording needs only clicks.

### 8.4 Launch plan (owner executes; Opus prepares drafts in `docs/launch/` only)

Order: (1) owner picks the name, checks GitHub, crates.io, major distro package names and a trademark search (USPTO/EUIPO/Indian IP registry) for conflicts; (2) private beta with 3-5 people from the IEEE branch on different distros, fix what they hit; (3) make the repo public with a tagged release; (4) IEEE student branch talk and write-up; (5) "Show HN" post: title states what it is plainly, first comment gives design, limits and what feedback is wanted; (6) r/linux, r/rust, r/netsec, r/blueteamsec - read each subreddit's self-promotion rules first, post on different days, answer every technical comment; (7) eBPF community channels. Drafts Opus writes: Show HN text, a 600-word technical blog post on the loss-accounting and follow-mode design, IEEE talk outline. Positioning in all of them: visibility and explainability, honest limits, not a security product.

## 9. Ethics, privacy, legal

9.1 Dual use. A system-wide process monitor can be used to watch other people. Mitigations built in: root-only install; service off by default; no stealth or hiding features (SKILL.md do-not-do list); the daemon appears under its own name in process lists and the journal; the GUI shows a permanent "monitoring all users on this machine" note when more than one human uid has processes; no content capture (I6). README states: use only on machines you own or administer with the knowledge of their users; monitoring others without consent may be illegal where you live. This is not legal advice; the owner should not present it as such.

9.2 Export and sharing. Traces contain usernames, home paths, hostnames, addresses, command lines. Default redaction on every export/report/record intended for sharing: home directory -> `~`, other users' homes -> `~user<N>`; username and hostname -> placeholders; argv values after `--password`, `--token`, `--secret`, `--key`, `-p` style flags and `KEY=VALUE` pairs with secret-like keys -> `<redacted>`; URLs with userinfo -> userinfo removed; IPs kept by default (needed for analysis) with `--redact-ips` mapping each to a stable pseudonym; decoy contents never exported. `--raw` requires an explicit flag and prints a warning. The export dialog shows a one-line reminder to review before sharing. Redaction is best-effort and the docs say so.

9.3 Real malware. Handling samples carries legal and safety risk that varies by country and by sample; the docs say this, say the tool is not designed to make it safe, and give only the VM protocol in 6.6.

9.4 Telemetry: none (D23). No crash reports. No update checks.

## 10. PROGRESS.md format (maintain exactly; newest entries at the bottom of the log)

```
# PROGRESS

## Current state            <- rewrite this block every time you stop
Updated: <YYYY-MM-DD HH:MM IST>
Milestone: M<n>   Current WP: WP<nn> <name>   Status: IN_PROGRESS | BLOCKED(E<n>) | DONE
Next action: <the single next concrete step>
Open questions for owner: <Q numbers from NEEDS_USER.md or "none">
Tree state: <clean | describe uncommitted work>
Last green gate: <milestone, date, commit>

## WP status
| WP | Name | Status | Verified on | Commit | Notes |
(one row per WP00..WP34; Status: TODO | IN_PROGRESS | DONE | BLOCKED(E<n>))

## Decisions made without the owner
- <date> WP<nn>: <decision> - <why> - <how to reverse>

## Deviations from the plan
- <date> WP<nn>: <what the plan said> -> <what was done> - <evidence> - <escalated as Q<n> | allowed by fallback>

## Log
### <date time> WP<nn> <name>
Did: <2-5 lines>
Verify command: `<exact command>`
Verify output (trimmed, real):
<fenced block>
Result: PASS | FAIL (<what failed, what you will try next>)
```

## 11. Test plan

| # | What | How | Expected | Runs where | Headless |
|---|---|---|---|---|---|
| T1 | Protocol encode/decode, escaping | unit + proptest + golden files | round-trip equality; no panic on garbage | CI, host | yes |
| T2 | Core state, limits, tree invariants | unit + proptest | caps hold; invariants hold for random sequences | CI, host | yes |
| T3 | Detector rules | replay fixtures (pos/neg/boundary) vs expected.json | exact rule ids, subjects, scores | CI, host | yes |
| T4 | Scoring and explanations | unit + golden text | worked example = 72; decay halves at 600 s | CI, host | yes |
| T5 | Kernel event correctness | `wl` ground truth vs observed, exact counts | equality for exec/fork/exit/open/rename/unlink/connect/listen | host root, VMs | yes |
| T6 | Loss accounting | flood with normal and tiny ring buffer | emitted = received + counted drops | host root, VMs | yes |
| T7 | Follow enforcement | followed tree vs unrelated workload | 0 events from unrelated; all descendants followed | host root, VMs | yes |
| T8 | Identity | BPF ProcKey vs /proc ProcKey, 200 processes | 200/200 equal | host root, VMs | yes |
| T9 | Hostile inputs to tracer | long paths, non-UTF-8, escape sequences, pid churn | flags set, safe rendering, no crash | host root | yes |
| T10 | Daemon server | many clients, slow client, bad frames, no-network strace | limits enforced; isolation; only AF_UNIX | host root | yes |
| T11 | End-to-end detection | simulators -> findings with evidence | expected finding per simulator | host root, VMs | yes |
| T12 | False positives | benign corpus replay | 0 high; <= 2 suspicious/hour, all explained | host, VM | yes |
| T13 | Overhead | `make bench` | thresholds in WP14 | host | yes |
| T14 | GUI model | unit tests on `Model` | sort/filter/pause/selection semantics | CI, host | yes |
| T15 | GUI widgets | egui_kittest against replay | all labels present; interactions change model | CI, host | yes |
| T16 | GUI rendering | Xvfb + software GL screenshot, non-blank check, Opus inspects PNG | 6 states show required elements | host | yes (virtual display) |
| T17 | GUI performance | stress replay, frame timing | no frame > 50 ms; < 10% core | host | yes |
| T18 | Glasshouse functional | demo sample -> exact report | counts in WP24 | VM, host | yes |
| T19 | Glasshouse adversarial | hostile probes + differ torture | all CONTAINED; caps respected | VMs only | yes |
| T20 | Real-sample pipeline | detonate.sh with harmless sample | report over serial; `-nic none`, `-snapshot` asserted | host (KVM) | yes |
| T21 | Fuzzing | cargo-fuzz, 10 min/target | 0 crashes | host | yes |
| T22 | Packaging | install/start/stop/remove per distro | clean install and removal | VMs | yes |
| T23 | Compatibility | `make vm-matrix` | COMPAT.md complete | VMs | yes |
| T24 | Text claims | grep tests for forbidden phrases and required 6.4 text | pass | CI | yes |
| T25 | Act mode | refusal matrix, pid reuse | every unsafe case refused | host root, VM | yes |
| T26 | Adversarial review | fresh subagent per milestone | findings fixed with regression tests | host | yes |

CI (GitHub Actions, private): T1-T4, T14, T15, T24, lint. Whether hosted runners can load these BPF programs is unknown `[VERIFY once; if yes add T5 smoke as a separate job]`. Everything else runs locally through `make`.

## 12. Risk register (probability x damage, highest first)

| # | Risk | Early-warning signal | Countermeasure |
|---|---|---|---|
| 1 | A chosen hook is rejected by the verifier or differs across kernels (d_path, security_* prototypes) | WP04/06/07 Verify fails in a VM; verifier log mentions helper or arg type | VM-first loading; prototype check per kernel before coding; stated fallbacks; escalate with evidence rather than switching to tracepoints silently |
| 2 | Opus works around failing tests or drifts from the plan over long autonomy | Tests edited in the same commit as a fix; `#[ignore]`; thresholds changed; PROGRESS.md lacks real output | SKILL.md rules 4-5; gate subagent diffs tests vs previous gate; CI check that fails on `#[ignore]` and on changes to threshold constants without a "Deviations" entry |
| 3 | Scope: 35 packages stall before a demoable core | M1 not done after ~15 sessions | Milestones are independently valuable; v0.1.0 tag after M3; M4-M6 can stop at any WP boundary |
| 4 | Host damage from an autonomous root agent (bad BPF, runaway test, hostile probe on host) | dmesg warnings; hostile tests referenced outside `vm/` | Host safety rules; VM-first; path allowlist; hostile suite hard-coded to refuse outside a VM (checks DMI product name / a marker file created by cloud-init) |
| 5 | Overhead too high system-wide (opens and syscalls) | WP14 misses thresholds | Levers listed in WP14; `syscalls=off`; follow mode as the low-overhead path |
| 6 | False positives make the tool look silly | WP18 exceeds thresholds; self-flagging | Benign corpus as regression; allowlist with reasons; conservative weights; wording "flagged", not "malware" |
| 7 | Sandbox gives false confidence or has an escape | Any ESCAPED probe; unprivileged userns unavailable | 6.4 text everywhere; fail closed; adversarial suite; VM-only for real samples |
| 8 | VM harness unusable (VirtualBox/KVM conflict, disk, images) | WP03 fails | Escalate E2/E5 early (WP00 checks); debian12 is the only hard requirement to proceed |
| 9 | GUI cannot be verified headless (GL under Xvfb, kittest API) | `make gui-shot` blank; kittest missing features | Model-level tests carry correctness; software GL env vars; if screenshots impossible, escalate E10 for a human look |
| 10 | Context loss between sessions causes rework or contradictory code | Re-implementing existing modules; PROGRESS.md stale | PROGRESS.md "Current state" discipline; CLAUDE.md pointer; ARCHITECTURE.md kept current; small WPs |
| 11 | Dependency API churn (libbpf-rs, egui) vs architect's memory | Compile errors following plan wording | `[VERIFY]` rule; read registry sources; pin versions; plan specifies behaviour, not API calls |
| 12 | Owner cannot explain the project in interviews | Owner has not read the code by M3 | LEARNING_PATH.md tied to files; module header comments; ARCHITECTURE.md |

## 13. Residual assumptions the architect could not remove

1. The exact libbpf-rs, libbpf-cargo, eframe/egui, egui_kittest, procfs, seccompiler APIs and feature names are not specified here on purpose; Opus must read the installed versions.
2. Every `[VERIFY]` item, most importantly: `bpf_d_path` legality at `security_file_open`; stability of the `security_*` prototypes from 5.15 to 6.19; io_uring coverage; the start_ticks equality; cgroup id = cgroupfs inode; LimitCORE=0 suppressing piped core handlers; the VirtualBox/KVM interaction on this host.
3. Benchmark and false-positive thresholds are engineering targets chosen without measurements on this machine.
4. Claude Code must be allowed to run shell commands (including sudo) without a human approving each one, or the run will stall on permission prompts; how the owner configures that is outside this package.
5. Ubuntu 24.04's AppArmor policy may make Glasshouse unavailable there without a system change; the plan treats that as a documented degradation.
6. Arch and Fedora cloud images and their package tooling may need per-distro adjustments the plan does not enumerate.
7. GitHub Actions minutes on the private repo are assumed sufficient for the light CI defined here.
8. Final name, trademark clearance, demo recording and all public actions remain with the owner.
