#!/usr/bin/env bash
# WP04 Verify, run as root inside a dev VM: start `sysscoped --dev --dump`,
# run /bin/true 100 times from a known parent, stop the daemon, and check the
# dump has exactly 100 FORK, 100 EXEC and 100 EXIT for that parent's children
# with the correct exe path. Also checks dmesg for new BPF/kernel warnings.
set -euo pipefail
BIN=/opt/sysscope/bin/sysscoped
OUT=$(mktemp -d)
dmesg_before=$(dmesg --level=err,warn | wc -l)

"$BIN" --dev --dump > "$OUT/dump.jsonl" 2> "$OUT/err.log" &
daemon=$!
for _ in $(seq 1 100); do grep -q 'tracing' "$OUT/err.log" && break; sleep 0.1; done
grep -q 'tracing' "$OUT/err.log" || { cat "$OUT/err.log"; exit 1; }

bash -c 'echo $$ > '"$OUT"'/parent; for ((i=0; i<100; i++)); do /bin/true; done'
sleep 1
kill -INT "$daemon"; wait "$daemon" || true
cat "$OUT/err.log"

python3 - "$OUT" <<'PY'
import json, sys, os
out = sys.argv[1]
parent = int(open(os.path.join(out, "parent")).read())
ev = [json.loads(l) for l in open(os.path.join(out, "dump.jsonl"))]
true_exe = os.path.realpath("/bin/true")
key = lambda p: (p["tgid"], p["start"])
forks = [e for e in ev if e["kind"]["k"] == "Fork" and e["proc"]["tgid"] == parent]
children = {key(e["kind"]["child"]) for e in forks}
execs = [e for e in ev if e["kind"]["k"] == "Exec" and key(e["proc"]) in children]
exits = [e for e in ev if e["kind"]["k"] == "Exit" and key(e["proc"]) in children]
good_exe = [e for e in execs if e["kind"]["exe"] == true_exe]
print(f"parent={parent} total_events={len(ev)} FORK={len(forks)} EXEC={len(execs)} "
      f"EXEC_exe_ok={len(good_exe)} EXIT={len(exits)} expected_exe={true_exe}")
if execs:
    print("sample exec:", json.dumps(execs[0]))
ok = len(forks) == 100 and len(children) == 100 and len(execs) == 100 \
    and len(good_exe) == 100 and len(exits) == 100
print("WP04 LIFECYCLE", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY
rc=$?
dmesg_after=$(dmesg --level=err,warn | wc -l)
if [ "$dmesg_after" -gt "$dmesg_before" ]; then
    echo "new dmesg err/warn lines:"; dmesg --level=err,warn | tail -n $((dmesg_after - dmesg_before))
    dmesg --level=err,warn | tail -n $((dmesg_after - dmesg_before)) | grep -Eiq 'bpf|BUG|WARNING|RCU' && { echo "DMESG NOT CLEAN"; exit 1; }
fi
echo "dmesg: no new bpf/BUG/WARNING/RCU lines"
exit $rc
