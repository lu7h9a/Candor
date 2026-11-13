# UNVERIFIED.md - what has not been verified, and why

| Item | WP | Why not verified | What would verify it |
|---|---|---|---|
| fedora (45) and arch guests boot and report BTF | WP03 | refused by the E5 free-RAM guard (5188-5616 MiB available vs 5722 needed), NEEDS_USER Q2 | `vm/run.sh fedora '...'` / `vm/run.sh arch '...'` when 6 GB is free or Q2 = A |
| Cloud image checksum files are not GPG-verified | WP03 | checksums are fetched over HTTPS from the distro's own server; signature files not checked | add gpg verification with the distro keys (needs gpg keyrings; optional) |
| Display-time neutralising of C1 controls / bidi overrides in valid UTF-8 | WP02 | wire escaping (4.5) leaves them; must be handled in CLI/GUI display code | WP13 / WP20 tests with U+009B and U+202E in a path |
| WP04 lifecycle on the host kernel 6.19 | WP04 | no passwordless sudo (Q1) | `make test-root` / `sudo ./target/release/sysscoped --dev --dump` |
| WP04 lifecycle on ubuntu2204 (5.15) | WP04 | E5 RAM guard refused the VM (5499 MiB) | `make vm-test DISTRO=ubuntu2204` |
| Leader-exits-first EXIT semantics | WP04 | needs the WP05 workload | `wl leader-exits-first` in WP05 |
