# UNVERIFIED.md - what has not been verified, and why

| Item | WP | Why not verified | What would verify it |
|---|---|---|---|
| fedora (45) and arch guests boot and report BTF | WP03 | refused by the E5 free-RAM guard (5188-5616 MiB available vs 5722 needed), NEEDS_USER Q2 | `vm/run.sh fedora '...'` / `vm/run.sh arch '...'` when 6 GB is free or Q2 = A |
| Cloud image checksum files are not GPG-verified | WP03 | checksums are fetched over HTTPS from the distro's own server; signature files not checked | add gpg verification with the distro keys (needs gpg keyrings; optional) |
| Display-time neutralising of C1 controls / bidi overrides in valid UTF-8 | WP02 | wire escaping (4.5) leaves them; must be handled in CLI/GUI display code | WP13 / WP20 tests with U+009B and U+202E in a path |
| WP04 lifecycle on the host kernel 6.19 | WP04 | no passwordless sudo (Q1) | `make test-root` / `sudo ./target/release/sysscoped --dev --dump` |
| R006 end-to-end with the beacon simulator | WP17 | plan contradiction (loopback-only simulator vs non-loopback rule), NEEDS_USER Q3 | owner answer, then the WP17 e2e itest |
| Simulator end-to-end tests for R001-R008 | WP16/17 | need the live daemon (WP12) and root (Q1) or a VM | itests driving testkit/sim against sysscoped |
