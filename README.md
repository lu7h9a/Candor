# SysScope

SysScope shows what the programs on a Linux computer are doing: the programs
they start, the files they open and the network connections they make. It
flags suspicious behaviour, such as reading SSH keys, running from a temp
folder, or rewriting many files at once, and explains each finding in plain
language with the events that prove it.

It has three parts:
- **sysscoped**: a root daemon that watches processes with eBPF.
- **sysscope-gui** and **sysscope**: a desktop app and a command-line tool,
  both unprivileged.
- **Glasshouse**: a sandbox that runs a program and reports what it touched.

> **The daemon watches the processes of every user on the computer.** Anyone
> in the `sysscope` group can see the command lines, opened files and
> connections of all processes. Add only people you would show that to.

## Requirements

- Linux 5.15 or newer with BTF. Tested on Debian 12 and Ubuntu 22.04 and
  24.04. Packages for Fedora and Arch are built the same way.
- systemd.
- bubblewrap, for Glasshouse.

## Install

Pick the package for your distribution from the releases:

    sudo apt install ./sysscope_*_amd64.deb      # Debian, Ubuntu
    sudo dnf install ./sysscope-*.x86_64.rpm     # Fedora
    sudo pacman -U sysscope-*.pkg.tar.zst        # Arch
    # anything else:
    tar xf sysscope-*-x86_64.tar.gz && cd sysscope-*-x86_64 && sudo ./install.sh

The service is installed but **not** started. To start it and let your user
connect:

    sudo systemctl enable --now sysscoped
    sudo usermod -aG sysscope "$USER"        # use the GUI and CLI
    sudo usermod -aG sysscope-act "$USER"    # also follow mode and pause/kill

Log out and back in after `usermod`.

## Use

    sysscope-gui                 # the desktop app
    sysscope status              # mode, process count, lost events
    sysscope top                 # busiest and most suspicious processes
    sysscope findings            # every finding, with its explanation
    sysscope detail PID          # files, connections, syscalls of one process
    sysscope follow PID          # watch only PID and its descendants
    sysscope glasshouse run FILE # run FILE in the sandbox, see what it touched

## Glasshouse

Glasshouse is a behaviour-demonstration sandbox, not a malware containment system. The program you run shares this computer's kernel. A kernel or sandbox vulnerability, a CPU side-channel, or a mistake in configuration could let it read your data or take over your account or the machine. Glasshouse does not hide that it is a sandbox, so a program may behave differently inside it. Run only programs you would accept losing this machine to, such as your own test scripts. For real or suspected malware use a dedicated virtual machine or a separate computer with no network, following docs/REAL_SAMPLES.md.

## Configuration

The rules and allowlist are built in. To override them, edit the files in
`/etc/sysscope/`; each file explains its format. Then restart the daemon:

    sudo systemctl restart sysscoped

Clients cannot change the rules.

## Remove

Use your package manager, or `sudo ./uninstall.sh` from the tarball. This
keeps `/etc/sysscope`; purge (or `uninstall.sh --purge`) removes it too.

## Security

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what SysScope protects,
who can do what, and the remaining risks.

## License

MIT, see [LICENSE](LICENSE). The BPF programs are dual MIT/GPL.
