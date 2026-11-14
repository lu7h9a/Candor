#!/usr/bin/env bash
# unit-wrap.sh sysscoped ARGS... - runs the daemon as a transient systemd
# service with the [Service] hardening of packaging/systemd/sysscoped.service
# (plan WP29 a). The root itests use it when SYSSCOPE_ITEST_WRAP points here.
# CAPS="CAP_A CAP_B" overrides CapabilityBoundingSet (capability probing).
# Stop it with SIGTERM (forwarded to the unit). SIGINT is forwarded too,
# but a background job of a non-interactive shell starts with SIGINT
# ignored and then cannot trap it.
# Test-only additions: the dev socket directory and the test temp directory
# are writable, because `--dev` and the tests use them.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
unit_file="$here/packaging/systemd/sysscoped.service"
props=()
while IFS= read -r line; do
    case "$line" in
    CapabilityBoundingSet=*) [ -n "${CAPS:-}" ] && line="CapabilityBoundingSet=$CAPS" ;;
    NoNewPrivileges=* | ProtectSystem=* | ReadWritePaths=* | ProtectHome=* | PrivateTmp=* | \
        RestrictAddressFamilies=* | IPAddressDeny=* | MemoryMax=* | SystemCallArchitectures=* | \
        LockPersonality=* | RestrictSUIDSGID=* | PrivateNetwork=* | PrivateDevices=* | \
        ProtectClock=* | ProtectHostname=* | ProtectKernelLogs=* | ProtectKernelModules=* | \
        ProtectKernelTunables=* | ProtectControlGroups=* | RestrictNamespaces=* | \
        RestrictRealtime=* | MemoryDenyWriteExecute=* | UMask=* | SystemCallFilter=*) ;;
    *) continue ;;
    esac
    props+=(-p "$line")
done < <(sed -n '/^\[Service\]/,/^\[/p' "$unit_file")
mkdir -p /run/sysscope-dev /run/sysscope /var/lib/sysscope
extra_rw=(/run/sysscope-dev)
[ -n "${TMPDIR:-}" ] && extra_rw+=("$TMPDIR")
unit="sysscope-probe-$$"
systemd-run --unit="$unit" --pipe --wait --collect --quiet \
    "${props[@]}" -p "ReadWritePaths=${extra_rw[*]}" \
    ${SUDO_GID:+--setenv=SUDO_GID=$SUDO_GID} -- "$@" &
runner=$!
fwd() { systemctl kill --signal="$1" "$unit.service" 2>/dev/null || true; }
trap 'fwd INT' INT
trap 'fwd TERM' TERM
rc=0
while kill -0 "$runner" 2>/dev/null; do
    wait "$runner" || rc=$?
done
exit "$rc"
