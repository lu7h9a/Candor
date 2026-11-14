# Security policy

Candor runs a root daemon and a sandbox, so security reports matter to us.
Thank you for taking the time to send one.

## Reporting a vulnerability

Please report privately through **GitHub Security Advisories**: on this
repository, open the **Security** tab and choose **Report a vulnerability**.
Do not open a public issue for a security problem.

Please include:
- the Candor version (`candor --version`), your distribution and kernel
  (`uname -r`);
- what an attacker can do, and from which position: an unprivileged local
  user, a member of the `candor` group, or a program inside Glasshouse;
- steps to reproduce, ideally a minimal script.

## What happens next

- We acknowledge your report within 7 days.
- We aim to have a fix within **90 days** of the report. We then publish an
  advisory and credit you, unless you prefer not to be named. If a fix takes
  longer, we tell you why and agree a new date with you.
- If the problem is already being exploited, we move faster and may publish
  a warning before the fix.

There is no bug bounty.

## In scope

- A local user or a program gaining privileges through `candord`, the
  socket, act mode or the Glasshouse helper.
- A program inside Glasshouse reading or changing anything outside the
  sandbox, or reaching the network, the daemon or the desktop.
- A traced program hiding its activity, or suppressing findings, in a way
  [docs/LIMITATIONS.md](docs/LIMITATIONS.md) does not already describe.
- Bytes from a traced program (file names, command lines) reaching your
  terminal or GUI unescaped.
- The packages or the release process.

## Out of scope

- A program with root hiding from Candor. Candor does not defend against
  root ([docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), section 3.5).
- Kernel vulnerabilities that a Glasshouse sample could use. Glasshouse is
  not a containment system, and the README says so.
- Detection gaps that are heuristics working as described: a finding that
  should or should not have fired. Please open a normal issue for those.
- Behaviour already listed in [docs/LIMITATIONS.md](docs/LIMITATIONS.md) or
  in the threat model's residual risks.

## Supported versions

Only the latest release receives security fixes.
