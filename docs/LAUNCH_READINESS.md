# Launch readiness - Candor 0.0.1

Written 2026-11-15 after the final audit (WP34) and the final adversarial
review. Everything below was run, not assumed; logs are under
`target/audit/` and `target/verify/` on the build machine.

## Verdict

Ready for a private pre-release. Two items need the owner before a public
launch: the benchmark consistency result and the release-time steps
(signing, name check). Nothing known is broken.

## What works (measured)

| Area | Result |
|---|---|
| Unit and integration tests (`make test`) | pass |
| Lint, integrity, docs-claims check (`make lint`) | pass |
| Root itests in a VM (debian12), after the final fixes | 52 / 52, including follow mode ending by itself |
| Root itests on the host (kernel 6.19) | 50 / 52; the 2 failures need the `candor-act` group the host does not have yet |
| Distro matrix: debian12, ubuntu2204, ubuntu2404, fedora 45, arch | 30 / 30 itests on each; every rule R001-R011 fires end to end; Glasshouse works everywhere except Ubuntu 24.04, where it is correctly reported unavailable (AppArmor userns policy) |
| Hostile sandbox probes (VM only) | PASS, guest stayed responsive |
| Packages (.deb, .rpm, Arch, tarball) | install, run, remove cleanly; tarball installs root-owned files; lintian 0 errors; rpmlint only `no-signature` |
| README quickstart, run verbatim in a fresh VM | pass |
| Fuzzing, 6 targets x 10 min | 0 crashes |
| False positives, 31.8 min of normal work | 0 high, 0 suspicious |
| Host kernel log after every BPF run | no BPF errors or warnings |

Overhead (latest run, docs/BENCH.md): cargo build +0.5 %, C build +3.9 %,
getppid loop +37 % (limit 60 %), open/close loop +25.5 % (limit 40 %),
follow mode within noise. Idle daemon 1.97 % of one core, 80 MiB RSS.

## Open before a public launch (owner)

1. **Benchmark consistency.** The open/close loop is well inside its
   overhead limit, but its round-to-round spread was 11.8 % on a quiet
   machine (rule: 10 %) after the script's own rerun. Either rerun
   `make bench` on an idle machine, or decide to change the spread rule
   (that is a threshold change and goes in docs/DEVIATIONS.md).
2. **Host groups**, so the last two host itests can run:
   `sudo systemd-sysusers packaging/sysusers/candor.conf` and
   `sudo usermod -aG candor,candor-act $USER`, then `make test-root`.
3. **Package signing** with your key at release time.
4. **Name check** for "Candor" (trademark, package-name collisions) before
   going public.
5. **One minute on a real desktop** with `candor-gui`: only Xvfb was
   available here.

## Known limitations (documented for users)

docs/LIMITATIONS.md and docs/THREAT_MODEL.md. The main ones: no defence
against root; inbound connections and most refused opens are not seen;
per-file byte counts in follow mode were never built; Glasshouse is a
demonstration sandbox, not containment, and relies on seccomp and an
unprivileged uid against kernel bugs.

## Launch checklist

- [ ] Items 1-5 above
- [ ] `git tag v0.0.1 && git push --tags` (release workflow builds a draft)
- [ ] Review the draft release and its SHA256SUMS, then publish it yourself
- [ ] Make the repository public only when you decide to
