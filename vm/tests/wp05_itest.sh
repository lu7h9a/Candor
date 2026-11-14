#!/usr/bin/env bash
# Runs every root integration test binary shipped to /opt/candor/bin
# (built on the host by `make itest-bin`), single-threaded, as root.
set -euo pipefail
export CANDOR_BIN_DIR=/opt/candor/bin
# Rule simulators shipped by vm/run.sh (rules_e2e).
export CANDOR_SIM_DIR=/opt/candor/sim
# Groups and the sandbox user from packaging/sysusers (act-mode and
# Glasshouse tests need them).
mkdir -p /usr/lib/sysusers.d
printf 'g candor -\ng candor-act -\nu candor-box - "Candor Glasshouse sandbox" / /usr/sbin/nologin\n' > /usr/lib/sysusers.d/candor.conf
systemd-sysusers /usr/lib/sysusers.d/candor.conf
dmesg_before=$(dmesg --level=err,warn | wc -l)
rc=0
for t in /opt/candor/bin/candor-itest-*; do
    echo "== $(basename "$t")"
    "$t" --test-threads=1 || rc=1
done
new=$(dmesg --level=err,warn | tail -n +$((dmesg_before + 1)))
if echo "$new" | grep -Eiq 'bpf|BUG|WARNING|RCU'; then echo "DMESG NOT CLEAN:"; echo "$new"; exit 1; fi
echo "dmesg: no new bpf/BUG/WARNING/RCU lines"
exit $rc
