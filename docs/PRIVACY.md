# Privacy

SysScope watches what every program on the computer does, so it handles
information about every user. This page says exactly what it collects, where
that information goes, and who can see it.

## Nothing leaves the machine

- The daemon makes **no network connections**. It runs in its own network
  namespace with no network at all (systemd `PrivateNetwork`,
  `IPAddressDeny=any`), and a test checks that it opens only local Unix and
  netlink sockets.
- There is no telemetry, no update check and no crash reporting.
- The desktop app and the CLI talk only to the local daemon.

## What is collected

Only metadata about what programs do (invariant I6):

| Collected | Example |
|---|---|
| Program path, process id, user id, parent | `/usr/bin/curl`, pid 4242, uid 1000 |
| The first 256 bytes of the command line | `curl https://example.com/file` |
| Files opened, renamed and deleted: the path and how it was opened | `/home/alice/.ssh/id_ed25519`, read |
| Outbound connections and listening sockets: address and port | `93.184.216.34:443` |
| How many times each system call was made | `openat` 1203 |
| CPU, memory, thread count and I/O totals, from `/proc` | 12 % CPU, 80 MB |
| A process's memory map, only when someone asks for it in the detail view | library paths and address ranges |

**Never collected:** the contents of files, anything a program reads or
writes, environment variables, keystrokes, passwords typed into programs, or
network traffic.

Command lines can contain secrets, such as a password passed as
`--password=...`. SysScope records them as they appear (truncated to 256
bytes), so whoever can see SysScope can see those. Exports hide the common
cases (see below).

## Where it is kept, and for how long

- **In the daemon's memory**, by default and with fixed limits:
  - processes that have exited are kept for 10 minutes;
  - up to 2,000 recent events per process and 100,000 overall;
  - one hour of CPU and memory history per process.
  
  It is all gone when the daemon stops.
- **On disk, only in these cases:**
  - **Glasshouse reports** in `/var/lib/sysscope/reports` (readable by root
    and the `sysscope` group, the newest 200 kept). They describe the sandbox
    run, not your real files.
  - **Learned baselines**, only if you enable the experimental rule R100:
    `/var/lib/sysscope/baselines.json` holds program paths and per-program
    behaviour statistics.
  - **Recordings**, only if the daemon is started with `--record FILE`
    (meant for development and fixtures): every event, to that file.
  - **Exports**, when you run `sysscope export` and save the output yourself.
- The daemon's log (the systemd journal) records who connected, and who used
  follow or act mode (user id and process id). It does not record events.

Uninstalling deletes `/run/sysscope` and `/var/lib/sysscope`.

## Who can see it

| Who | Sees |
|---|---|
| root | everything |
| members of the `sysscope` group | every process of every user: command lines, files, connections, findings. Memory maps only of their own processes. Membership is close to root-level read access to process activity, so grant it carefully. |
| members of `sysscope-act` | the same, plus pausing or killing their own processes and switching on follow mode |
| other users | nothing: they cannot connect to the daemon |

The installed package adds nobody to these groups; you choose who to add.

## Exports and sharing

`sysscope export` and saved reports are **redacted by default**:
- your home folder becomes `~`, other users' homes `~user1`, `~user2`…;
- your username and hostname become `<user>` and `<host>`;
- values of secret-looking options (`--password`, `--token`, `--secret`,
  `--key`, `-p`) and `KEY=VALUE` pairs with secret-like names become
  `<redacted>`;
- `user:password@` is removed from URLs;
- with `--redact-ips`, every IP address becomes a stable placeholder
  (`ip1`, `ip2`…).

Redaction is best effort: read an export before you share it. `--raw` turns
redaction off.
