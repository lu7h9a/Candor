#!/bin/sh
# uninstall.sh [--purge] - removes what install.sh installed (the list is
# MANIFEST); /etc/candor is kept unless --purge. Groups and the sandbox
# user are left, as a package manager would.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "uninstall.sh: run as root"; exit 1; }
purge=0; [ "${1:-}" = "--purge" ] && purge=1
systemctl disable --now candord.service >/dev/null 2>&1 || true
while read -r f; do
    case "$f" in
    /etc/candor/*) [ "$purge" -eq 1 ] || continue ;;
    esac
    rm -f "$f"
done < "$here/MANIFEST"
rmdir /usr/share/doc/candor 2>/dev/null || true
rm -rf /run/candor /var/lib/candor
[ "$purge" -eq 1 ] && rm -rf /etc/candor
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Candor removed."
