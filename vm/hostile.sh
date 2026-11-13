#!/usr/bin/env bash
# hostile.sh <distro> - WP25: runs testkit/hostile in a test VM (never on the
# host). Copies the release binaries, embeds hostile.py and run_all.sh,
# starts the suite in the background inside the guest, and while it runs
# measures how long a trivial SSH command takes (guest responsiveness per
# probe; the plan's bar is 5 s during the fork and memory bombs).
source "$(dirname "$0")/lib.sh"
d="${1:-}"; [ -n "$d" ] || die "usage: vm/hostile.sh <distro>"
set +e  # lib.sh sets -e; a slow or failed SSH probe is a measurement here, not an error
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
"$here/run.sh" "$d" "$(cat "$here/tests/wp00_tools.sh")" > /dev/null 2>&1 || die "installing test tools failed"
"$here/run.sh" "$d" "$("$here/embed.sh" "$repo/testkit/hostile/hostile.py:/tmp/hostile.py" "$repo/testkit/hostile/run_all.sh:/tmp/run_all.sh")
rm -f /tmp/hostile.done /tmp/hostile.log; echo starting > /tmp/hostile.phase
nohup bash /tmp/run_all.sh > /tmp/hostile.log 2>&1 < /dev/null &
echo launched" || die "could not start the suite"
declare -A worst
deadline=$(( $(date +%s) + 3600 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    t0=$(date +%s%N)
    out=$(timeout 30 bash -c "source '$here/lib.sh'; vm_ssh '$d' 'cat /tmp/hostile.phase; if test -f /tmp/hostile.done; then echo DONE; fi'" 2>/dev/null)
    rc=$?
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    phase=$(printf '%s\n' "$out" | head -1); [ $rc -eq 0 ] || { phase=unknown; ms=30000; }
    [ "${worst[$phase]:-0}" -ge "$ms" ] || worst[$phase]=$ms
    printf '%s\n' "$out" | grep -q DONE && break
    sleep 2
done
source "$here/lib.sh"; set +e
vm_ssh "$d" 'cat /tmp/hostile.log'
echo "== guest responsiveness (slowest SSH round trip per phase)"
fail=0
for p in "${!worst[@]}"; do
    printf '  %-12s %6d ms\n' "$p" "${worst[$p]}"
    case $p in forkbomb|membomb|unknown) [ "${worst[$p]}" -le 5000 ] || fail=1 ;; esac
done
res=$(vm_ssh "$d" 'cat /tmp/hostile.done 2>/dev/null')
[ "$res" = pass ] && [ $fail -eq 0 ] && { echo "VM-HOSTILE $d PASS"; exit 0; }
echo "VM-HOSTILE $d FAIL (suite: ${res:-no result}, responsiveness ok: $([ $fail -eq 0 ] && echo yes || echo no))"; exit 1
