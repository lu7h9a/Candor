# NEEDS_USER

Questions for the owner. Newest at the bottom. Answered questions are marked RESOLVED with the answer recorded underneath.

## Q1 - Allow the build agent to use sudo without a password            RESOLVED (case E1, raised 2026-11-13 05:58)
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
Update 2026-11-14: the owner created /etc/sudoers.d/90-sysscope-agent (chmod 0440, `visudo -c` parsed OK) and `sudo -n true` briefly printed OK, but minutes later the file was gone and `sudo -n` again asks for a password. Still open; I did not recreate it.
RESOLVED 2026-11-14: the owner re-ran option A; /etc/sudoers.d/90-sysscope-agent is present (0440 root:root, 31 bytes) and `sudo -n true` succeeds from the agent shell, which has no cached sudo timestamp.
Update 2026-11-14: after the first host run the owner ran `sudo rm /etc/sudoers.d/90-sysscope-agent`. The file was still present right after and `sudo -n true` still succeeded, but the owner's intent is clear: I treat passwordless sudo as withdrawn and do not use sudo until the owner says otherwise. Packages stay installed.
RESOLVED again 2026-11-14: the owner re-ran option A (tee, then chmod 0440 and `visudo -c`: parsed OK). Passwordless sudo is in use again.

## Q2 - Not enough free memory to start test virtual machines reliably            RESOLVED (case E5, raised 2026-11-13 06:40)
Blocks: VM steps of WP03 (fedora, arch), WP04-WP10 VM verification, WP23-WP26, WP30-WP31 (they all boot a 2 GiB test VM).
What I need from you: choose A or B.
Why I need it: the plan says not to start a VM when less than 6 GB of RAM is free. Free RAM on this machine moves between 5.2 and 6.2 GB depending on what you have open (Brave and the Claude apps use about 6 GB together). Debian 12, Ubuntu 22.04 and Ubuntu 24.04 VMs booted fine; Fedora and Arch were refused by the 6 GB check at 5.2-5.6 GB free.
Exactly what to do:
  Option A: reply "A" (lets me start a VM when at least guest RAM + 2 GiB = 4 GiB is free; the VM uses 2 GiB, so the host keeps at least 2 GiB plus 19 GiB swap).
  Option B: close browser windows you do not need while I work, so more than 6 GB stays free.
How to check it worked: `free -m` shows an "available" value above 6144 (option B).
Options (if it is a choice): A) lower the VM start line to 4 GiB free  B) keep 6 GB and free memory   My recommendation: A, because a 2 GiB guest with 4 GiB free leaves the desktop comfortable and VM tests are needed for every kernel work package.
If I hear nothing: I keep the 6 GB line, retry the check each time a VM step starts, and run VM steps only when 6 GB happens to be free. Nothing is lowered without your answer.
RESOLVED 2026-11-14: owner chose A ("lower the threshold"). vm/lib.sh now starts a VM when guest RAM + 2 GiB (4 GiB for a 2 GiB guest) is available.

## Q3 - Plan contradiction: the beaconing simulator can never trigger the beaconing rule            RESOLVED (case E6, raised 2026-11-13 09:55)
Blocks: only the end-to-end check of rule R006 in WP17 (replay tests for R006 already pass).
What I need from you: choose A or B.
Why I need it: the plan says network simulators may only talk to 127.0.0.0/8 (loopback, this machine), and asks for a beacon simulator with a local listener. But rule R006 is defined to ignore loopback destinations. So the simulator, as specified, can never trigger the rule it is meant to test, and the plan gives no fallback.
Exactly what to do:
  1. Reply with "Q3: A" or "Q3: B".
How to check it worked: nothing to run; I record your answer in NEEDS_USER.md and PROGRESS.md.
Options (if it is a choice): A) keep both as written; the end-to-end test loads a test-only rules override that lets R006 count loopback (production rules unchanged)  B) let the simulator connect to this machine's own non-loopback address (for example its LAN IP) with a local listener, so no rule changes are needed   My recommendation: A, because the shipped rule stays exactly as specified and the simulator never touches a real network interface.
If I hear nothing: replay fixtures keep covering R006; its end-to-end check stays unverified and is listed in docs/UNVERIFIED.md.
RESOLVED 2026-11-14: owner chose A. The R006 end-to-end test loads a test-only rules override that lets R006 count loopback; the shipped rules stay unchanged.

## Q4 - Create SysScope's system groups and sandbox user on this machine            RESOLVED (case E1-related, raised 2026-11-14)
Blocks: the host run of the act-mode group test (WP27) and the host Glasshouse runs (WP23-WP25). Everything else of `make test-root` now runs on the host.
What I need from you: run one command once.
Why I need it: SysScope uses the groups `sysscope` (socket access) and `sysscope-act` (act mode) and the system user `sysscope-box` (the Glasshouse sandbox user, no home, no shell). They are defined in packaging/sysusers/sysscope.conf and are normally created by installing the package. Creating them writes /etc/group and /etc/passwd, which is outside the paths I may write, so I will not do it myself.
Exactly what to do:
  1. `sudo systemd-sysusers /home/lu7h9a/project-new/packaging/sysusers/sysscope.conf`
  (To undo later: `sudo userdel sysscope-box; sudo groupdel sysscope-act; sudo groupdel sysscope`)
How to check it worked: `getent group sysscope-act && id sysscope-box` prints a group line and a uid line.
Options (if it is a choice): A) create them now  B) leave them until the package is installed (WP30); those host checks stay pending   My recommendation: A, because the users are inert (no login, no home) and the host checks then cover everything.
If I hear nothing: the two host checks stay pending; VM results (all passing) stand for them.
RESOLVED 2026-11-14: the owner ran systemd-sysusers: groups sysscope (968), sysscope-act (967), user sysscope-box (966).

## Q5 - Follow-mode overhead target for micro-benchmarks cannot be met            RESOLVED (case E6, raised 2026-11-14)
Blocks: WP14 only (the overhead gate). Everything else continues.
What I need from you: choose A, B or C.
Why I need it: the plan wants every benchmark at most 3% slower while SysScope follows an unrelated process. The real-work benchmarks meet it, but two tight-loop micro-benchmarks cannot. Measured on this laptop, `performance` governor, 10 rounds, after all the plan's levers:
  - clean `cargo build`: on +0.6%, follow -0.4% (limit 5% / 3%), pass
  - unpack + `make -j` C project: on +4.8%, follow +2.6%, pass
  - 500 000 x open/close: on +23.9% (limit 40%) pass, follow +20.2% (limit 3%), FAIL
  - 5 000 000 x getppid: on +38.2% (limit 60%) pass, counting off -0.1% (limit 5%) pass, follow +59.7% (limit 3%), FAIL
  - idle daemon 1.73% of a core, RSS 75 MiB, pass
  The cause: kernel hooks (the file-open hook, and the syscall entry and exit tracepoints) fire for every process before any BPF filter can skip it. The plan also asks for syscall latency of the followed tree in follow mode (WP08), which needs the syscall hooks attached exactly then. So an unrelated process doing nothing but syscalls pays the hook cost.
Exactly what to do:
  1. Reply with "Q5: A", "Q5: B" or "Q5: C".
Options (if it is a choice):
  A) Keep the design; set the follow-mode limits for these two micro-benchmarks to the "on" limits (open/close 40%, getppid 65%). Follow mode keeps syscall counts and latency.
  B) In follow mode, detach the syscall hooks unless a syscall view is open for the followed tree (getppid follow drops to about 0%). Syscall latency then appears only while it is being looked at. open/close follow stays about 20%, so its limit becomes 40% as in A.
  C) Like A, but report the follow-mode micro numbers as information only and keep 3% for the macro benchmarks, which are the ones users feel.
  My recommendation: C. Real workloads (builds) stay within 3% in follow mode, and the micro loops are worst cases by design.
If I hear nothing: WP14 is recorded as "macro, idle and on-mode targets met; follow-mode micro targets escalated", and I continue with WP29. Nothing is relaxed in bench/thresholds.toml without your answer.
RESOLVED 2026-11-14: owner chose B ("q5 b multi follow later"): syscall hooks in follow mode only while a viewer looks; open/close follow limit 40%; multi-follow becomes a later feature.
