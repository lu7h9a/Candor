# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/). The version is defined once,
in the workspace `Cargo.toml`.

## [Unreleased]

### Changed
- Follow mode ends by itself once every process of the followed tree has
  exited.
- Act mode can be switched on in `/etc/candor/candord.toml`
  (`enable_act = true`).
- A trusted `git` reading an SSH private key is now reported (R001, lower
  confidence) instead of allowlisted.

### Security
- `/etc/candor` files not owned by root, or writable by other users, are
  ignored.
- The tarball installer installs root-owned files whoever unpacked it.
- Act mode never pauses or kills a display server or session manager you
  own, in any session.
- Glasshouse refuses runs when it was reported unavailable at start, and
  checks the helper again before each run.

## [0.0.1] - 2026-11-15

The first build to have packages. This is a pre-release.

### Added
- **candord**, a root daemon that watches processes with CO-RE eBPF:
  - programs started, forks and exits;
  - files opened, renamed and deleted;
  - outbound connections and listening sockets;
  - per-process syscall counts;
  - follow mode for one process tree.
- **Detection rules R001–R009, R011 and R012**, each finding explained in plain language with
  the events that prove it, plus **R100**, an experimental baseline rule that
  is off by default.
- **candor-gui**, a desktop app, and **candor**, a CLI. Both are
  unprivileged and talk to the daemon over a Unix socket. The CLI can export,
  replay recordings and run Glasshouse.
- **Glasshouse**, a bubblewrap sandbox that runs a program against decoy
  files and reports what it read, changed, deleted and connected to. It is
  not a malware containment system; see the README.
- **Act mode**, experimental and off by default: pause, resume or kill a
  process. It needs the `candor-act` group.
- Lost events are accounted for: kernel budget, ring buffer, scratch,
  undecodable records, a full process table, and probe runs the kernel
  skipped.
- Packages for Debian and Ubuntu (.deb), Fedora (.rpm) and Arch (PKGBUILD),
  plus a tarball with install and uninstall scripts. The service is
  installed but not enabled.
- A hardened systemd unit with five capabilities; see
  `docs/THREAT_MODEL.md`.
- `candor --version` prints the version, the git commit and the protocol
  version.

[Unreleased]: https://github.com/lu7h9a/candor/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/lu7h9a/candor/releases/tag/v0.0.1
