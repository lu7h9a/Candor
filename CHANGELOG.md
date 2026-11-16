# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/). The version is defined once,
in the workspace `Cargo.toml`.

## [Unreleased]

### Changed (desktop app redesign)
- A calm, minimal look: one dark theme, Inter and JetBrains Mono bundled
  (SIL OFL, licences in /usr/share/doc/candor/fonts), colour only for
  selection (teal), findings (red) and caution (amber).
- Three pages: Processes, Findings, Glasshouse. The process table shows
  five columns by default (process, CPU, memory, connections, score); the
  others are in a column picker. Stat cards show CPU, memory, events per
  second and the number of events not recorded.
- Process detail: Overview (charts, "What it did", finding cards with the
  events behind them), Map, and Events.
- Glasshouse is one page in three states (start, running, report) with
  numbered steps, a one-click "Try an example", drag and drop, a summary
  sentence and a before/after list.
- Keyboard: `/` search, Esc back, arrows and Enter in the table, `f`
  follow.

### Added
- **Access map**: everything a process and its children touched (files,
  connections, listening sockets, the processes it started) as a graph,
  with filters, grouping of system files and big folders, a time window,
  search, and a side panel with who touched what and when.
- Access map: processes as squares in the middle, files on a ring around
  them, connections on an outer ring; kinds and lines colour coded by what
  was done, with a legend; clicking a process or file shows its details
  (inode, opens, user, parent, CPU, memory and more).
- Process tree collapsed by default, with arrows and Expand all. In the
  table, a program's own sub-processes (a browser's many processes) fold
  under it behind an arrow.
- Every column is shown from the start; a checkbox in each header hides
  it and the Columns menu brings it back.
- Menu > Help > Command-line guide: every `candor` command with an
  example to copy. The menu always shows the exact command to join
  candor-act (`sudo usermod -aG candor-act USER-NAME`) with an example.
- Menu: "Add me to candor-act" (the system asks for the password), "Open
  Candor when I log in", "Start minimised".
- Plain explanations: what each kind of lost event means and which
  processes lost the most; why memory maps of other users' processes are
  not shown; why Glasshouse cannot run (with the common reasons).
- `candor --color=auto|always|never` (and `NO_COLOR`): `top` marks
  findings with a red or amber dot and ends with a summary line,
  `findings` prints each finding as a title and three labelled lines, and
  `glasshouse run` ends with the same summary sentence as the app.

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
