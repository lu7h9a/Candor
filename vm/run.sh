#!/usr/bin/env bash
# run.sh <distro> <cmd> - run <cmd> as root in the guest and return its exit code.
# Boots the guest if needed and copies host-built release binaries
# (target/release/sysscope*) to /opt/sysscope/bin and testkit/sim to
# /opt/sysscope/sim first. Guests build nothing.
source "$(dirname "$0")/lib.sh"
d="${1:-}"; cmd="${2:-}"
[ -n "$d" ] && [ -n "$cmd" ] || die "usage: vm/run.sh <distro> '<command>'"
here="$(cd "$(dirname "$0")" && pwd)"
"$here/up.sh" "$d" >&2
distro_info "$d"
repo="$(cd "$here/.." && pwd)"
bins=$(find "$repo/target/release" -maxdepth 1 -type f -perm -u+x -name 'sysscope*' 2>/dev/null || true)
if [ -n "$bins" ]; then
    # shellcheck disable=SC2046
    tar -C "$repo/target/release" -cf - $(for b in $bins; do basename "$b"; done) |
        vm_ssh "$d" 'sudo mkdir -p /opt/sysscope/bin && sudo tar --no-same-owner -C /opt/sysscope/bin -xf -'
fi
# The harmless rule simulators the root itests run (rules_e2e).
if [ -d "$repo/testkit/sim" ]; then
    tar -C "$repo/testkit" -cf - --exclude=__pycache__ sim |
        vm_ssh "$d" 'sudo rm -rf /opt/sysscope/sim && sudo mkdir -p /opt/sysscope && sudo tar --no-same-owner -C /opt/sysscope -xf -'
fi
# As an installed package would: root-owned, writable by root only (the
# daemon runs only a root-owned Glasshouse helper).
vm_ssh "$d" 'sudo chown -R root:root /opt/sysscope && sudo chmod -R go-w /opt/sysscope'
set +e
vm_ssh "$d" "sudo bash -c $(printf '%q' "$cmd")"
rc=$?
set -e
exit "$rc"
