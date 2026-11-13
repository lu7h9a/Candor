# UNVERIFIED.md - what has not been verified, and why

| Item | WP | Why not verified | What would verify it |
|---|---|---|---|
| fedora (45) and arch guests boot and report BTF | WP03 | refused by the E5 free-RAM guard (5188-5616 MiB available vs 5722 needed), NEEDS_USER Q2 | `vm/run.sh fedora '...'` / `vm/run.sh arch '...'` when 6 GB is free or Q2 = A |
| Cloud image checksum files are not GPG-verified | WP03 | checksums are fetched over HTTPS from the distro's own server; signature files not checked | add gpg verification with the distro keys (needs gpg keyrings; optional) |
| C1/bidi neutralising in the GUI | WP02/WP20 | done for CLI (core display.rs, unit-tested); GUI must use the same function | WP20 kittest with U+202E in a path |
| Local time zone in explanations | WP13 | UTC shown; local zone needs zoneinfo parsing | WP20/WP33 |
| WP04 lifecycle on the host kernel 6.19 | WP04 | no passwordless sudo (Q1) | `make test-root` / `sudo ./target/release/sysscoped --dev --dump` |
| R006 end-to-end with the beacon simulator | WP17 | plan contradiction (loopback-only simulator vs non-loopback rule), NEEDS_USER Q3 | owner answer, then the WP17 e2e itest |
| Simulator end-to-end tests for R001-R008 | WP16/17 | need the live daemon (WP12) and root (Q1) or a VM | itests driving testkit/sim against sysscoped |
| Pid reuse against the kernel maps (followed_tgid, budget, sys_count) | gate | keys now include start time; forcing pid reuse needs ns_last_pid in a VM (planned for WP27) | WP27 pid-reuse itest |
| Idle clients holding all 8 slots | gate | accepted: only root and sysscope-group members can connect; documented in THREAT_MODEL (WP29) | - |
| Fedora 45 itests | WP31 | all 30 passed once (kernel 7.2.11) before the gate fixes; re-run in WP31 | make vm-matrix |
| GUI CPU and look on a real GPU and real desktop | WP21 | only Xvfb + llvmpipe here; GUI threads 6-7 %, whole process ~33 % with software rendering | owner runs sysscope-gui on the desktop (human check, WP34) |
