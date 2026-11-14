#!/usr/bin/env bash
# package.sh - builds every package inside a fresh ubuntu2204 guest, the
# oldest supported glibc (plan WP30, D21), and copies them to
# target/packages. The guest is bigger than a test guest (Rust release
# build): VM_MEM_MB=6144 VM_CPUS=4 VM_DISK_GB=30 unless set.
set -euo pipefail
export VM_MEM_MB="${VM_MEM_MB:-6144}" VM_CPUS="${VM_CPUS:-4}" VM_DISK_GB="${VM_DISK_GB:-30}"
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
source "$here/lib.sh"
d=ubuntu2204
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)
"$here/down.sh" "$d" >/dev/null 2>&1 || true   # a fresh guest with the big disk
"$here/up.sh" "$d" >&2
# Source: tracked and new (not ignored) files; no build output, no git.
(cd "$repo" && git ls-files -co --exclude-standard | grep -v '^fuzz/corpus/' |
    tar --owner=0 --group=0 -cf - -T -) |
    vm_ssh "$d" 'sudo rm -rf /root/src && sudo mkdir -p /root/src && sudo tar -C /root/src -xf -'
commit=$(git -C "$repo" rev-parse --short=12 HEAD)
vm_ssh "$d" "sudo bash -c 'cd /root/src && SYSSCOPE_ITEST=1 SYSSCOPE_GIT_COMMIT=$commit packaging/build.sh $ver'"
rm -rf "$repo/target/packages"; mkdir -p "$repo/target/packages"
vm_ssh "$d" 'sudo tar -C /root/out -cf - .' | tar -C "$repo/target/packages" -xf -
"$here/down.sh" "$d" >/dev/null
ls -l "$repo/target/packages"
