#!/usr/bin/env bash
# WP12: daemon RSS after 10 minutes of process/file/network churn (< 300 MiB).
set -eu
BIN=/opt/sysscope/bin
"$BIN/sysscoped" --dev 2>/tmp/sysscoped.err &
sleep 3
pid=$(grep -o 'pid [0-9]*' /tmp/sysscoped.err | head -1 | cut -d' ' -f2)
[ -n "$pid" ] || { cat /tmp/sysscoped.err; exit 1; }
end=$((SECONDS + 600))
rounds=0
while [ $SECONDS -lt $end ]; do
    "$BIN/sysscope-wl" --dir /tmp/churn exec 50 fork 50 open-write 200 rename 50 unlink 50 connect-tcp 20 >/dev/null
    rm -rf /tmp/churn
    rounds=$((rounds + 1))
done
rss_kb=$(awk '/VmRSS/ {print $2}' /proc/$pid/status)
hwm_kb=$(awk '/VmHWM/ {print $2}' /proc/$pid/status)
kill -TERM "$pid"; wait "$pid" || true
echo "rounds=$rounds daemon VmRSS=${rss_kb} kB VmHWM=${hwm_kb} kB"
[ "$rss_kb" -lt $((300 * 1024)) ] && echo "WP12 RSS PASS" || { echo "WP12 RSS FAIL"; exit 1; }
