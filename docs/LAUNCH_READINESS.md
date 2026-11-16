# Launch readiness - Candor 0.0.1

Written 2026-11-15 after the final audit (WP34) and the final adversarial
review; updated 2026-11-16 after the desktop app redesign (PR #2) and the
first release. Everything below was run, not assumed; logs are under
`target/audit/` and `target/verify/` on the build machine.

## Verdict

Released privately as v0.0.1 (2026-11-16, built and checked by the
release workflow; installed from the release .deb on the owner's machine
and checked there). Before a public launch the owner still has: the
benchmark consistency result, package signing and the name check. Nothing
known is broken.

## What works (measured)

| Area | Result |
|---|---|
| Unit and integration tests (`make test`) | pass |
| Lint, integrity, docs-claims check (`make lint`) | pass |
| Root itests in a VM (debian12), after the final fixes | 52 / 52, including follow mode ending by itself |
| Root itests on the host (kernel 6.19) | all pass: 50 earlier, and the 6 act tests (including the 2 that needed the `candor-act` group) on 2026-11-16 once the owner's session had the group |
| Installed release on the owner's machine | `candor_0.0.1-1_amd64.deb` from the v0.0.1 release: service active, `candor status` reports all features including Glasshouse; the README's Glasshouse example ran and reported "It read a decoy SSH key and created one file", 0 events lost |
| Desktop app (redesign, PR #2) | `make test` 187 passed; map stress 150/2000 objects under 9 ms worst frame; live 40 s under load, slowest frame 3.9 ms; used by the owner on the real desktop |
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
2. ~~Host groups~~: done 2026-11-16; the act itests pass on the host.
3. **Package signing** with your key (v0.0.1 is unsigned; the release
   notes point to SHA256SUMS).
4. **Name check** for "Candor" (trademark, package-name collisions) before
   going public.
5. ~~One minute on a real desktop~~: done; the owner has used the GUI.
6. **Wayland**: not checked (no compositor on the build machine).
7. **Tray icon**: needs a library under the Unlicense, which `deny.toml`
   does not allow yet; owner's decision.

## Known limitations (documented for users)

docs/LIMITATIONS.md and docs/THREAT_MODEL.md. The main ones: no defence
against root; inbound connections and most refused opens are not seen;
per-file byte counts in follow mode were never built; Glasshouse is a
demonstration sandbox, not containment, and relies on seccomp and an
unprivileged uid against kernel bugs.

## Launch checklist

- [ ] Open items 1, 3, 4, 6, 7 above
- [x] `git tag v0.0.1 && git push --tags` (release workflow built the draft)
- [x] Draft checked (SHA256SUMS, contents, version) and published, 2026-11-16
- [ ] Make the repository public only when you decide to
