#!/bin/sh
# install.sh - installs SysScope from this tarball (for distros without a
# .deb, .rpm or Arch package). Run as root from the unpacked directory.
# The service is installed but not enabled. Existing files in /etc/sysscope
# are kept. Undo with uninstall.sh (keeps /etc/sysscope; --purge removes it).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "install.sh: run as root (sudo ./install.sh)"; exit 1; }
cd "$here/root"
find . -type d | while read -r d; do mkdir -p "/$d"; done
find . ! -type d | while read -r f; do
    case "$f" in
    ./etc/sysscope/*) [ -e "/$f" ] && continue ;;
    esac
    cp -a "$f" "/$f"
done
chown -R root:root /usr/bin/sysscoped /usr/bin/sysscope /usr/bin/sysscope-gui /usr/bin/sysscope-glasshouse
systemd-sysusers /usr/lib/sysusers.d/sysscope.conf || true
systemctl daemon-reload >/dev/null 2>&1 || true
cat /usr/share/doc/sysscope/postinstall-message.txt
