#!/usr/bin/env bash
# WP23: availability is detected by trying bubblewrap as sysscope-box; when it
# is not possible, run-local refuses with a reason and leaves nothing behind.
set -u
BIN=/opt/sysscope/bin
id sysscope-box >/dev/null 2>&1 || { printf 'g sysscope -\nu sysscope-box - "SysScope Glasshouse sandbox" / /usr/sbin/nologin\n' > /tmp/s.conf; systemd-sysusers /tmp/s.conf; }
"$BIN/sysscope-glasshouse" availability 2>/dev/null; arc=$?
printf '#!/bin/sh\nid\n' > /tmp/p.sh; chmod +x /tmp/p.sh
"$BIN/sysscope-glasshouse" run-local /tmp/p.sh > /tmp/o 2> /tmp/e; rrc=$?
grep -v GLIBC /tmp/e; grep -v GLIBC /tmp/o | head -3
leftover=$(ls /var/lib/sysscope/glasshouse 2>/dev/null | wc -l)
echo "availability rc=$arc run-local rc=$rrc leftover_run_dirs=$leftover"
# Expected: unavailable only where the kernel/AppArmor blocks user namespaces.
expect=available
[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ] && expect=unavailable
[ "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)" = 0 ] && expect=unavailable
echo "expected: $expect"
if [ $expect = unavailable ]; then
    [ $rrc -eq 4 ] && grep -q 'Glasshouse unavailable: ' /tmp/e && [ "$leftover" -eq 0 ] && echo "WP23 UNAVAILABLE-CORRECTLY PASS" || { echo "WP23 AVAILABILITY FAIL"; exit 1; }
else
    [ $arc -eq 0 ] && [ $rrc -eq 0 ] && grep -q 'uid=1000(victim)' /tmp/o && echo "WP23 AVAILABLE PASS" || { echo "WP23 AVAILABILITY FAIL"; exit 1; }
fi
