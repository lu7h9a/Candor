# UNVERIFIED.md - what has not been verified, and why

Last reconciled 2026-11-15 after the final audit (WP34). Rows closed in the
audit are listed at the end with the evidence that closed them.

| Item | WP | Why not verified | What would verify it |
|---|---|---|---|
| Cloud image checksum files are not GPG-verified | WP03 | checksums are fetched over HTTPS from the distro's own server; signature files not checked | add gpg verification with the distro keys (optional; affects only the test VMs) |
| GUI CPU and look on a real GPU and real desktop | WP21 | only Xvfb + llvmpipe here; GUI threads 6-7 %, whole process ~33 % with software rendering | owner runs candor-gui on the desktop for a minute |
| Home directories reloaded when /etc/passwd changes | WP29 | needs a write to /etc/passwd, outside the allowed write paths on the host | a VM test that adds a user while the daemon runs and checks R001's `~/` for that user |
| Package signatures (.deb, .rpm) | WP30 | signing needs the owner's key; rpmlint reports no-signature | owner signs at release |
| Per-file bytes read/written for followed processes (plan D12) | WP33 | not built (no fexit vfs_read/vfs_write probes); fields stay 0 and are not shown | build the probes (follow mode only) and an itest with exact byte counts |
| Benchmark consistency for 500 000 x open/close (tracer on) | WP34 | overhead +24.3 % and +25.5 % (limit 40 %) in two final runs, but the round-to-round spread was 29.4 % (machine busy) and 11.8 % (quiet) against the 10 % rule, after the script's own rerun; every other benchmark passed | owner decides: rerun on an idle machine, or change the spread rule (a threshold change, recorded in DEVIATIONS) |
| Glasshouse against a kernel bug reachable from a nested user namespace | WP34 | only seccomp and the unprivileged uid stand in the way; no extra layer (e.g. Landlock) was added | accepted residual risk, stated in the README and THREAT_MODEL |

## Closed in the final audit

| Item | Evidence |
|---|---|
| fedora (45) and arch guests; Fedora itests | `make vm-matrix`: 30/30 root itests on debian12, ubuntu2204, ubuntu2404, fedora 45 (7.2.11) and arch (7.2.11); docs/COMPAT.md |
| R006 and the simulators R001-R011 end to end | same matrix: every rule row passes on all five distros |
| WP04 lifecycle on the host kernel 6.19 | host root itests: 50 passed after the final merge; the act suite (6/6) passed on 2026-11-16 once the session had the `candor-act` group |
| Act and follow-group itests on the host | 6/6 on 2026-11-16 |
| Pid reuse against the kernel maps | act.rs pid-reuse itest forcing ns_last_pid, `make vm-test` |
| Man pages | packaging/man, installed by every package; lintian has no manual-page warning |
| C1/bidi neutralising in the GUI; local time zone | the GUI renders through core display.rs; explanations take the viewer's UTC offset |
