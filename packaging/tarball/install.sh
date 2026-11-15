#!/bin/sh
# install.sh - installs Candor from this tarball (for distros without a
# .deb, .rpm or Arch package). Run as root from the unpacked directory.
# The service is installed but not enabled. Existing files in /etc/candor
# are kept. Undo with uninstall.sh (keeps /etc/candor; --purge removes it).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "install.sh: run as root (sudo ./install.sh)"; exit 1; }
cd "$here/root"
find . -type d | while read -r d; do mkdir -p "/$d"; done
find . ! -type d | while read -r f; do
    case "$f" in
    ./etc/candor/*) [ -e "/$f" ] && continue ;;
    esac
    # Root-owned whatever unpacked the tarball: a user-owned unit, sysusers
    # file or /etc/candor file would let that user change what runs as root
    # or switch detection off (final review finding).
    cp -a --no-preserve=ownership "$f" "/$f"
    chown root:root "/$f"
done
systemd-sysusers /usr/lib/sysusers.d/candor.conf || true
systemctl daemon-reload >/dev/null 2>&1 || true
cat /usr/share/doc/candor/postinstall-message.txt
