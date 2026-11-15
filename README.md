# Candor

**See what the programs on your Linux machine are really doing.**

Candor shows what programs on your Linux machine are doing and explains why
some behaviour looks suspicious. It is a visibility tool with explainable
heuristics, not an antivirus, and it cannot be relied on to stop or contain
malware.

![The process table, system-wide](docs/img/system-wide.png)

## What it does

| | |
|---|---|
| **Live process view** | Every process with its CPU, memory, threads, files opened, connections and children, updated twice a second. You can see it as a table or as a tree. |
| **Kernel-level tracing** | Programs started, files opened, renamed and deleted, outbound connections and listening sockets, and per-process system-call counts. Captured with eBPF inside the kernel, so it sees what programs do even when they skip the usual libraries. |
| **Explained findings** | Eleven rules for behaviour worth a second look: reading SSH keys or browser passwords, running from a temp folder, running with no file on disk, writing startup files, mass file rewrites (ransomware), regular beaconing to the internet, port scans, event floods, a document viewer starting a shell, attempts to inject into another process, and touching a Glasshouse decoy. An experimental twelfth, "unlike its usual self", is off by default. Each finding says what happened, why it is flagged, what harmless explanation might fit, and lists the exact events behind it. |
| **Follow mode** | Watch one program and everything it starts, with extra detail such as system-call timing, while the rest of the system is ignored. |
| **Glasshouse** | Run a program in a sandbox full of decoy files (fake SSH keys, documents, photos) and get a before/after report of what it read, changed, deleted and tried to connect to. |
| **Honest about gaps** | Events Candor could not record are counted and shown, never silently dropped. |
| **Private** | Everything stays on the machine. The daemon makes no network connections at all, and exports hide personal details by default. |

![A finding with its explanation and evidence](docs/img/detail-findings.png)

## Quickstart (60 seconds)

Download the package for your system from the
[Releases](https://github.com/lu7h9a/candor/releases) page. On Debian or
Ubuntu:

```bash
sudo apt-get install -y ./candor_0.0.1-1_amd64.deb
sudo systemctl enable --now candord
sudo usermod -aG candor "$USER"
candor --version
sudo candor status
sudo candor top --sort score -n 10
```

After you log out and back in, you can drop the `sudo` and open the desktop app
with `candor-gui`.

The package installs the service but never starts it by itself. **The daemon
sees the processes of every user on the computer**, and so does anyone in the
`candor` group. Add only people you would show that to, and run Candor
only on computers you own or are responsible for: it records what other
people's programs do, and watching others without their knowledge may be
unlawful where you live.

Other systems:

```text
sudo dnf install ./candor-0.0.1-1.x86_64.rpm            # Fedora
makepkg -si                                               # Arch, with the PKGBUILD from the release
tar xf candor-0.0.1-x86_64.tar.gz && sudo ./candor-0.0.1-x86_64/install.sh   # anything else
```

## Try it

See what a program does in the Glasshouse sandbox:

```bash
printf '#!/bin/sh\ncat ~/.ssh/id_ed25519 > /dev/null\necho hi > ~/Documents/note.txt\n' > try.sh
sudo candor glasshouse run try.sh
```

Read the findings so far, each with its explanation:

```bash
sudo candor findings
```

Other commands:

```text
candor detail PID          files, connections, syscalls and findings of one process
candor follow PID          watch only PID and what it starts; candor unfollow to stop
candor tail                live events
candor export --format json > snapshot.json    personal details redacted by default
```

Following needs root or the `candor-act` group, because while it is on,
Candor ignores every other process for everyone:

```text
sudo usermod -aG candor-act "$USER"     then log out and back in
```

The same group also allows pausing, resuming and killing your own processes
from Candor (act mode). Act mode is experimental and off until root turns it
on with `enable_act = true` in `/etc/candor/candord.toml` and restarts
`candord`. Display servers and session managers you own are never paused or
killed.

## Glasshouse

![A Glasshouse report](docs/img/glasshouse-report.png)

Glasshouse is a behaviour-demonstration sandbox, not a malware containment system. The program you run shares this computer's kernel. A kernel or sandbox vulnerability, a CPU side-channel, or a mistake in configuration could let it read your data or take over your account or the machine. Glasshouse does not hide that it is a sandbox, so a program may behave differently inside it. Run only programs you would accept losing this machine to, such as your own test scripts. For real or suspected malware use a dedicated virtual machine or a separate computer with no network, following docs/REAL_SAMPLES.md.

Glasshouse needs bubblewrap. On Ubuntu 24.04 the default AppArmor policy
blocks the user namespaces it uses, so Candor reports it as unavailable
there and says why. Candor does not change that setting.

## How it works

```text
            your desktop                                   root
  +-------------------------+                 +--------------------------------+
  | candor-gui / candor     |  Unix socket    | candord                        |
  | (unprivileged)          | <-------------> |  rules + scoring (candor-core) |
  +-------------------------+  group candor   |  process table, history        |
                                              |  /proc sampler (1 Hz)          |
                                              +---------------^----------------+
                                                              | ring buffer
                                              +---------------+----------------+
                                              | kernel: eBPF probes            |
                                              |  exec, fork, exit, file open,  |
                                              |  rename, unlink, connect,      |
                                              |  listen, ptrace, syscall counts|
                                              +--------------------------------+
  Glasshouse: candord -> systemd transient unit -> bubblewrap sandbox
              (decoy home, no network, seccomp) -> differ -> report
```

The kernel probes only observe; they never change what programs do. The
daemon runs as a hardened systemd service with five Linux capabilities and no
network access. The desktop app and CLI run as you and talk to it only over
the socket. More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

- Linux 5.15 or newer with BTF type information. Every supported
  distribution ships it.
- systemd, and bubblewrap for Glasshouse.
- Tested on Debian 12, Ubuntu 22.04, Ubuntu 24.04, Fedora 45 and Arch:
  [docs/COMPAT.md](docs/COMPAT.md).

## Limitations

Candor is a visibility tool. It does not block anything, and a determined
attacker with root can hide from it. It does not see inbound connections or
attempts the kernel refused, and its rules are heuristics that will sometimes
flag harmless programs and miss harmful ones. The full list is in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the parts fit together |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What is protected, who can do what, remaining risks |
| [docs/PRIVACY.md](docs/PRIVACY.md) | What is collected, where it goes, who can see it |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | What Candor cannot see or do |
| [docs/REAL_SAMPLES.md](docs/REAL_SAMPLES.md) | Studying real malware safely, in a separate VM |
| [docs/DEMO.md](docs/DEMO.md) | A 60-second demo |
| [docs/COMPAT.md](docs/COMPAT.md), [docs/BENCH.md](docs/BENCH.md), [docs/FP_REPORT.md](docs/FP_REPORT.md) | Test results: distributions, overhead, false positives |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Configuration

The rules and the allowlist are built in. To change them, edit the files in
`/etc/candor/`; each one explains its format. Then restart the daemon with
`sudo systemctl restart candord`. Clients cannot change the rules.

## Remove

```bash
sudo apt-get purge -y candor
```

`remove` keeps `/etc/candor`; `purge` deletes it too. For the tarball, run
`sudo ./uninstall.sh` (add `--purge` to remove `/etc/candor` as well).

## Building from source

```text
make setup        # build dependencies (Debian/Ubuntu/Kali)
make release      # target/release/{candord,candor,candor-gui,candor-glasshouse}
make test         # unprivileged tests
make test-root    # kernel tests (needs root; best inside a VM)
make package      # all packages, built in an Ubuntu 22.04 VM
```

## How this was built

Candor was built with AI assistance. The design and the verification
approach are documented in `docs/`: every kernel change is tested in virtual
machines first, results are recorded with the commands that produced them,
and independent reviews hunted for bugs and security holes before release.
What has not been verified is listed openly in
[docs/UNVERIFIED.md](docs/UNVERIFIED.md).

## License

MIT, see [LICENSE](LICENSE). The eBPF programs are dual MIT/GPL.
