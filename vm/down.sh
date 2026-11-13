#!/usr/bin/env bash
# down.sh [distro] - stop one guest, or all guests when no distro is given.
# The overlay disk and seed are deleted; the verified base images stay cached.
source "$(dirname "$0")/lib.sh"
targets=("$@"); [ ${#targets[@]} -gt 0 ] || targets=("${ALL_DISTROS[@]}")
for d in "${targets[@]}"; do
    distro_info "$d"
    st="${VM_STATE}/${d}"
    if vm_is_up "$d"; then
        pid=$(cat "${st}/qemu.pid")
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
        kill -9 "$pid" 2>/dev/null || true
        echo "vm: $d stopped"
    fi
    rm -rf "$st"
done
