# Limitations

What Candor cannot see or do. These are design limits, not bugs; the
threat model ([THREAT_MODEL.md](THREAT_MODEL.md)) gives the security view of
the same points.

## What it is not

- **Not an antivirus.** It does not block, quarantine or clean anything, and
  it never acts on a finding by itself. The experimental act mode (pause,
  resume, kill) only does what a person asks.
- **Not protection against root.** A program running as root can stop the
  daemon, change its rules, unload its probes, or hide with a kernel
  rootkit loaded before or after Candor.
- **Glasshouse is not a containment system.** The program shares your
  kernel; a kernel or sandbox bug could let it out. Use a separate machine
  or virtual machine for real malware ([REAL_SAMPLES.md](REAL_SAMPLES.md)).

## What it does not see

- **Inbound connections**: connections other computers make to yours (accept),
  and UDP traffic sent without a connect call. Outbound connects and
  listening sockets are seen.
- **Attempts the kernel refused.** If a program tries to open a file it has
  no permission for, the attempt is not seen; only opens that succeed reach
  the probe.
- **What is read or written.** File contents and network data are never
  captured, by design. Bytes read and written per file are not measured
  either (planned, not built).
- **Long command lines and paths.** Only the first 256 bytes of a command
  line are kept. Paths longer than 512 bytes are cut, and marked as cut.

## When it can lose events

Every loss is counted and shown ("lost events" in `candor status` and in
the GUI). What you see is then incomplete:

- A single program producing more than about 2,000 events per second (bursts
  up to 4,000) loses the excess. Its start (exec) and exit do not count
  against this limit. Doing
  this for three seconds is itself a finding (R008, event flood).
- When the whole system produces events faster than the daemon reads them,
  the kernel's buffer fills and events are dropped.
- The kernel sometimes skips a probe while that probe is already running on
  the same CPU. This is more common on fully preemptible kernels (Arch,
  Fedora). These skips are counted per probe ("skipped by the kernel"), so
  which program lost the event is not known.
- More than 8,192 processes alive at once: the extra ones are not tracked
  ("untracked").

## When identity is uncertain

- **Programs that exit within microseconds** may be gone before the daemon
  can check their executable. They are then treated as untrusted (the safe
  answer for the allowlist), and their path cannot be checked for a private
  view.
- **Private namespaces and containers.** A program's path is what the program
  itself sees. When that differs from the real file on your system (a
  container, a chroot, a bind mount), Candor marks it "(in a private
  namespace)". Trust is checked against the real file.
- **Trusted programs can be misused.** The allowlist trusts root-owned
  executables in root-owned directories. A trusted program that loads
  attacker code (a malicious plugin, `LD_PRELOAD`) keeps that trust.

## Rules are heuristics

They flag behaviour worth a second look, and they can be wrong both ways:

- **False positives**: a backup tool reading SSH keys, or an installer
  running from `/tmp`. Each finding lists harmless explanations, and the
  allowlist in `/etc/candor/allow.toml` silences what you trust. On the
  recorded everyday workloads there were none ([FP_REPORT.md](FP_REPORT.md)),
  but your machine is not those workloads.
- **Missed behaviour**: rules have thresholds, so slower or quieter activity
  passes. Some examples of the defaults:
  - beaconing (R006) needs at least 6 connections over at least a minute,
    with a regular rhythm (variation under 15 %), so a beacon with random
    timing is missed;
  - mass rewrites (R005) need 20 files within 10 seconds;
  - a port scan (R007) needs 100 destinations within 10 seconds.
- **Credential reads (R001)** match file paths: reaching the same file
  through another name (a hard link, a bind mount) is not matched.
- **"Unlike its usual self" (R100)** is experimental and off by default. It
  needs many runs of a program before it can judge it.

## Follow mode

While Candor follows one process tree, the kernel ignores every other
process: detection is reduced for everyone. That is why it needs root or the
`candor-act` group, every switch is logged, and every viewer sees the mode.

## Platform

- Linux 5.15 or newer with BTF type information. Without BTF the daemon
  refuses to start and explains why (exit code 3).
- Glasshouse needs bubblewrap and unprivileged user namespaces. Ubuntu 24.04's
  default AppArmor policy blocks them, so Glasshouse is unavailable there,
  and Candor says so.
- Times in explanations are shown in UTC.
- The GUI has been tested headless with software rendering. A check on a
  real desktop with a real graphics card is still pending
  ([UNVERIFIED.md](UNVERIFIED.md)).
