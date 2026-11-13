# NEEDS_USER

Questions for the owner. Newest at the bottom. Answered questions are marked RESOLVED with the answer recorded underneath.

## Q1 - Allow the build agent to use sudo without a password            (case E1, raised 2026-11-13 05:58)
Blocks: WP00 package install, and every work package that loads eBPF or runs root tests: WP04-WP10, WP12, WP14, WP16-WP18, WP23-WP25, WP27-WP31, WP34 (and the M1-M6 milestone gates, which include `make test-root`).
What I need from you: choose A or B below and run its commands in a terminal once.
Why I need it: `sudo -n true` fails with "a password is required", so I cannot install the missing build packages or load eBPF programs. On this machine eBPF always needs root (`kernel.unprivileged_bpf_disabled = 2`, `kernel.perf_event_paranoid = 3`), so there is no non-root way to test the tracer, and I must not type passwords myself.
Exactly what to do:
  Option A (what the plan assumes; unblocks everything):
  1. `echo "lu7h9a ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/90-sysscope-agent`
  2. `sudo chmod 0440 /etc/sudoers.d/90-sysscope-agent && sudo visudo -c`
  (To undo later: `sudo rm /etc/sudoers.d/90-sysscope-agent`)
  Option B (installs the missing packages only; root tests stay blocked):
  1. `sudo apt-get update && sudo apt-get install -y libelf-dev libzstd-dev libbpf-dev libseccomp-dev strace jq hyperfine clang-format cloud-image-utils lintian lld`
How to check it worked: `sudo -n true && echo OK` prints `OK` (option A), or `dpkg -s libelf-dev | grep Status` prints `Status: install ok installed` (option B).
Options (if it is a choice): A) passwordless sudo for user lu7h9a  B) install the packages yourself, keep the password prompt   My recommendation: A, because without it no eBPF code can ever be loaded or tested, which is most of the project.
If I hear nothing: I keep building and testing everything that does not need root (scaffold, protocol, VM harness, core state, rule engine, GUI model and views from replay data). Root work packages stay blocked.
