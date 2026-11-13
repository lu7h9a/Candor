#!/usr/bin/env bash
# sysroot.sh - unpack the libelf/libzstd development files and clang-format
# into target/sysroot when they are not installed system-wide (no root needed, nothing outside the
# repo is written). Packages are fetched with `apt-get download`, which checks
# them against the signed Kali index; both are on the plan's pre-authorised list.
# Once libelf-dev and libzstd-dev are installed with apt this script is a no-op.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
root=target/sysroot
pkgs=()
if [ ! -f /usr/include/libelf.h ] && [ ! -e "$root/usr/lib/x86_64-linux-gnu/libelf.so" ]; then
    pkgs+=(libelf-dev libzstd-dev)
fi
if ! command -v clang-format >/dev/null && [ ! -x "$root/usr/lib/llvm-21/bin/clang-format" ]; then
    pkgs+=(clang-format-21)
fi
[ ${#pkgs[@]} -gt 0 ] || exit 0
mkdir -p "$root/debs"
(cd "$root/debs" && apt-get download "${pkgs[@]}")
for p in "${pkgs[@]}"; do dpkg-deb -x "$root"/debs/"${p}"_*.deb "$root"; done
# The packaged link symlinks are relative (libelf.so -> libelf.so.1); point
# them at the runtime libraries that are installed system-wide.
for lib in libelf libzstd; do
    so=$(ls /usr/lib/x86_64-linux-gnu/${lib}.so.1* 2>/dev/null | head -1 || true)
    [ -n "$so" ] && ln -sfn "$so" "$root/usr/lib/x86_64-linux-gnu/${lib}.so"
done
echo "sysroot: unpacked ${pkgs[*]} into $root"
