#!/usr/bin/env bash
# sysroot.sh - unpack the libelf/libzstd development files into target/sysroot
# when they are not installed system-wide (no root needed, nothing outside the
# repo is written). Packages are fetched with `apt-get download`, which checks
# them against the signed Kali index; both are on the plan's pre-authorised list.
# Once libelf-dev and libzstd-dev are installed with apt this script is a no-op.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
root=target/sysroot
if [ -f /usr/include/libelf.h ] && [ -f /usr/include/zstd.h ]; then
    exit 0
fi
if [ -f "$root/usr/include/libelf.h" ] && [ -f "$root/usr/include/zstd.h" ]; then
    exit 0
fi
mkdir -p "$root/debs"
(cd "$root/debs" && apt-get download libelf-dev libzstd-dev)
for deb in "$root"/debs/*.deb; do dpkg-deb -x "$deb" "$root"; done
echo "sysroot: unpacked $(ls "$root"/debs) into $root"
