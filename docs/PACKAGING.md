# Packaging (plan WP30)

`make package` builds every package inside a fresh ubuntu2204 guest, the
oldest supported glibc (`vm/package.sh` runs `packaging/build.sh` there) and
writes them to `target/packages`:

| File | For |
|---|---|
| `sysscope_<ver>-1_amd64.deb` | Debian 12, Ubuntu 22.04, Ubuntu 24.04 |
| `sysscope-<ver>-1.x86_64.rpm` | Fedora |
| `PKGBUILD` + `sysscope.install` + the tarball | Arch (`makepkg`) |
| `sysscope-<ver>-x86_64.tar.gz` | anything else (`install.sh`, `uninstall.sh [--purge]`) |

All four install the same tree (`packaging/stage.sh`):
- `/usr/bin/{sysscoped,sysscope,sysscope-gui,sysscope-glasshouse}`, stripped. The Glasshouse helper sits next to the daemon, which runs only a root-owned helper from its own directory.
- The unit in `/usr/lib/systemd/system`. It is installed but never enabled.
- The sysusers file, which creates the `sysscope` and `sysscope-act` groups and the `sysscope-box` user.
- Comment-only `/etc/sysscope/*.toml` override files (conffiles; the defaults are built in).
- The desktop entry and icon.
- README, LICENSE, THREAT_MODEL and REAL_SAMPLES under `/usr/share/doc/sysscope`.

After installing, each package prints `packaging/postinstall-message.txt`. It says how to enable the service and join the groups, and that the daemon watches every user's processes.

Removing a package deletes the unit, `/run/sysscope` and `/var/lib/sysscope`. On Debian, `remove` keeps `/etc/sysscope` and `purge` deletes it. RPM and pacman delete unmodified config files and keep modified ones as `.rpmsave`/`.pacsave`. The groups and the sandbox user stay, as with any package that creates accounts.

Binaries: they need at most GLIBC_2.35, and libbpf is linked statically. The runtime libraries are libelf, zlib and libzstd.

## Verify (`vm/pkgtest.sh <distro>`, `TARBALL=1` for the tarball)

Each guest does the same steps:
1. Install the package and check the post-install message.
2. Check the service is not enabled.
3. Check the groups and the sandbox user exist.
4. Start the service. Check the socket is `660 root:sysscope` and that `sysscope status` works.
5. Stop the service and remove the package.
6. Run a `find` over /usr /etc /var /opt, compared with the listing from before the install: nothing of SysScope may be left.

Result, 2026-11-14 (0.0.1): all OK on debian12, ubuntu2204, ubuntu2404, fedora (.rpm) and arch (makepkg + pacman); the tarball also passed on debian12.

## Lint

lintian: 0 errors. Warnings:
- `initial-upload-closes-no-bugs`: not a Debian archive upload.
- `maintainer-script-calls-systemctl`: prerm stops the service directly; there is no debhelper.
- `no-manual-page` for the four binaries: man pages are planned with the docs (WP32).

rpmlint: 1 error, `no-signature`. Packages are signed with the owner's key at release time; this needs a credential, so it is the owner's step (escalation E9). Warnings:
- `no-manual-page-for-binary` x4 (as above).
- `invalid-license MIT`: the license is MIT (SPDX identifier `MIT`); the rpmlint in the Ubuntu build guest does not accept it with its default configuration.
- `dangerous-command-in-%postun rm`: it removes `/run/sysscope` and `/var/lib/sysscope` only, on erase.
