#!/usr/bin/env bash
# Runs every root integration test binary shipped to /opt/sysscope/bin
# (built on the host by `make itest-bin`), single-threaded, as root.
set -euo pipefail
export SYSSCOPE_BIN_DIR=/opt/sysscope/bin
# Groups and the sandbox user from packaging/sysusers (act-mode and
# Glasshouse tests need them).
mkdir -p /usr/lib/sysusers.d
printf 'g sysscope -\ng sysscope-act -\nu sysscope-box - "SysScope Glasshouse sandbox" / /usr/sbin/nologin\n' > /usr/lib/sysusers.d/sysscope.conf
systemd-sysusers /usr/lib/sysusers.d/sysscope.conf
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
