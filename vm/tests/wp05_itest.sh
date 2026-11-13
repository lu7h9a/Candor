#!/usr/bin/env bash
# Runs every root integration test binary shipped to /opt/sysscope/bin
# (built on the host by `make itest-bin`), single-threaded, as root.
set -euo pipefail
export SYSSCOPE_BIN_DIR=/opt/sysscope/bin
dmesg_before=$(dmesg --level=err,warn | wc -l)
rc=0
for t in /opt/sysscope/bin/sysscope-itest-*; do
    echo "== $(basename "$t")"
    "$t" --test-threads=1 || rc=1
done
new=$(dmesg --level=err,warn | tail -n +$((dmesg_before + 1)))
if echo "$new" | grep -Eiq 'bpf|BUG|WARNING|RCU'; then echo "DMESG NOT CLEAN:"; echo "$new"; exit 1; fi
echo "dmesg: no new bpf/BUG/WARNING/RCU lines"
exit $rc
