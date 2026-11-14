#!/bin/sh
# uninstall.sh [--purge] - removes what install.sh installed (the list is
# MANIFEST); /etc/sysscope is kept unless --purge. Groups and the sandbox
# user are left, as a package manager would.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "uninstall.sh: run as root"; exit 1; }
purge=0; [ "${1:-}" = "--purge" ] && purge=1
systemctl disable --now sysscoped.service >/dev/null 2>&1 || true
while read -r f; do
    case "$f" in
    /etc/sysscope/*) [ "$purge" -eq 1 ] || continue ;;
    esac
    rm -f "$f"
done < "$here/MANIFEST"
rmdir /usr/share/doc/sysscope 2>/dev/null || true
rm -rf /run/sysscope /var/lib/sysscope
[ "$purge" -eq 1 ] && rm -rf /etc/sysscope
systemctl daemon-reload >/dev/null 2>&1 || true
echo "SysScope removed."
