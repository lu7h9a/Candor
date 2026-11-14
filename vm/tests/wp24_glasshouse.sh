#!/usr/bin/env bash
# WP24 Verify (VM only, root). The demo sample testkit/sim/fake_malware.py is
# shipped to /opt/candor/sim by vm/run.sh.
# 1. demo run through daemon + CLI -> exact report counts;
# 2. calibration: the same sample under strace -f -c (run-local
#    --calibrate, seccomp off) -> opens counted independently of BPF;
# 3. the same run while following an unrelated process (followed_cgroup).
set -u
BIN=/opt/candor/bin
SAMPLE=/opt/candor/sim/fake_malware.py
mkdir -p /usr/lib/sysusers.d && printf 'g candor -\ng candor-act -\nu candor-box - "Candor Glasshouse sandbox" / /usr/sbin/nologin\n' > /usr/lib/sysusers.d/candor.conf
systemd-sysusers /usr/lib/sysusers.d/candor.conf
rm -rf /var/lib/candor/reports
"$BIN/candord" --dev > /tmp/d.out 2> /tmp/d.err &
dpid=$!
for _ in $(seq 1 100); do [ -S /run/candor-dev/candor.sock ] && break; sleep 0.1; done
sleep 1
fail=0
if ! "$BIN/candor-glasshouse" availability; then
    # Correct outcome here: the daemon must not offer Glasshouse and the CLI
    # must say so cleanly.
    "$BIN/candor" glasshouse run "$SAMPLE" > /tmp/u.out 2> /tmp/u.err; rc=$?
    cat /tmp/u.err
    kill -INT $dpid; wait $dpid
    if [ $rc -ne 0 ] && grep -q "Glasshouse is not available on this system" /tmp/u.err; then
        echo "WP24 UNAVAILABLE-CORRECTLY PASS"; exit 0
    fi
    echo "WP24 UNAVAILABLE FAIL"; exit 1
fi
"$BIN/candor" --json status | grep -q '"glasshouse"' && echo "OK   daemon offers glasshouse" || { echo "FAIL feature flag"; fail=1; }

run_demo() { # $1 = output prefix
    "$BIN/candor" --json glasshouse run "$SAMPLE" > "$1.json" 2> "$1.err"
    echo "glasshouse run rc=$?"
}
check_report() { # $1 = report json; prints counts, exit 1 on mismatch
python3 - "$1" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
D = r["decoys"]
has = lambda d, s: s in d["states"]
read = sorted(d["path"] for d in D if has(d, "read"))
mod = [d for d in D if has(d, "modified") and has(d, "renamed")]
dele = [d for d in D if has(d, "deleted")]
rose = [d for d in mod if d["entropy_after"] is not None and d["entropy_after"] >= d["entropy_before"] + 1.0]
conns = sum(c["count"] for c in r["connections"])
rules = sorted({f["rule"] for f in r["findings"]})
loss = r["loss"]
print("read:", read)
print("modified+renamed:", len(mod), "entropy rose:", len(rose), "e.g.", mod[0]["entropy_before"] if mod else None, "->", mod[0]["entropy_after"] if mod else None)
print("deleted:", len(dele), "created:", [(c["path"], c["kind"]) for c in r["created"]])
print("connections:", [(c["addr"], c["port"], c["count"]) for c in r["connections"]])
print("findings:", rules)
print("loss:", loss, "notes:", r["notes"], "exit:", r["exit_code"], "timed_out:", r["timed_out"])
ok = (read == ["/home/victim/.aws/credentials", "/home/victim/.ssh/id_ed25519"]
      and len(mod) == 20 and len(rose) == 20
      and all(d["path"].startswith("/home/victim/Documents/") and d["new_path"].endswith(".locked") for d in mod)
      and len(dele) == 10 and all(d["path"].startswith("/home/victim/Pictures/") for d in dele)
      and [c["path"] for c in r["created"]] == ["/home/victim/README_RESTORE.txt"]
      and conns == 1 and r["connections"][0]["addr"] == "203.0.113.10" and r["connections"][0]["port"] == 443
      and {"R012", "R001", "R005", "R004"} <= set(rules)
      and loss["ringbuf"] == 0 and loss["budget"] == 0
      and r["exit_code"] == 0 and r["limitation"].startswith("Glasshouse is a behaviour-demonstration sandbox"))
# Opens from bubblewrap on (the calibration run counts the same span).
tl = r["timeline"]
start = next(i for i, e in enumerate(tl) if e["kind"]["k"] == "Exec" and e["kind"]["exe"] == "/usr/bin/bwrap")
opens = sum(1 for e in tl[start:] if e["kind"]["k"] == "Open")
print("OPENS_FROM_BWRAP", opens, "timeline", len(tl), "processes", len(r["children"]))
print("REPORT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY
}

echo "== 1. demo run (system-wide)"
run_demo /tmp/r1
grep -v '^Glasshouse is a behaviour' /tmp/r1.err | head -20
check_report /tmp/r1.json > /tmp/r1.check; c1=$?; cat /tmp/r1.check
[ $c1 -eq 0 ] || fail=1
"$BIN/candor" glasshouse run "$SAMPLE" 2>/dev/null > /tmp/r1.txt
sed -n '1,40p' /tmp/r1.txt

echo "== 2. calibration (strace -f, successful opens only, seccomp off, run-local)"
"$BIN/candor-glasshouse" run-local --calibrate "$SAMPLE" > /tmp/cal.out 2> /tmp/cal.err
echo "run-local --calibrate rc=$?"
sed -n '/--- strace ---/,$p' /tmp/cal.out > /tmp/strace.txt
all_ok=$(grep -cE '(open|openat|openat2|creat)\(' /tmp/strace.txt)
opath=$(grep -E '(open|openat|openat2|creat)\(' /tmp/strace.txt | grep -c 'O_PATH')
data_ok=$((all_ok - opath))
bpf_opens=$(awk '/^OPENS_FROM_BWRAP/ {print $2}' /tmp/r1.check)
echo "successful opens under strace: $all_ok, of which O_PATH (no data access, never reach security_file_open): $opath, data opens: $data_ok"
echo "daemon trace opens from bwrap on: $bpf_opens (budget+ringbuf drops 0)"
grep -E 'O_PATH' /tmp/strace.txt | sed -E 's/^[0-9]+ +//' | cut -c1-90 | sort | uniq -c | sort -rn | head -5
[ -n "$bpf_opens" ] && [ "$data_ok" -eq "$bpf_opens" ] && echo "OK   every data open of the box is attributed" || { echo "FAIL attribution"; fail=1; }

echo "== 3. demo run while following an unrelated process"
sleep 600 & spid=$!
"$BIN/candor" follow $spid
run_demo /tmp/r3
check_report /tmp/r3.json > /tmp/r3.check; c3=$?; tail -3 /tmp/r3.check
[ $c3 -eq 0 ] || fail=1
"$BIN/candor" unfollow; kill $spid

echo "== cleanup and storage"
mount | grep -q /var/lib/candor/glasshouse && { echo "FAIL run dir still mounted"; fail=1; }
left=$(ls -A /var/lib/candor/glasshouse 2>/dev/null | wc -l)
echo "leftover entries in /var/lib/candor/glasshouse: $left"; [ "$left" -eq 0 ] || fail=1
ls -l /var/lib/candor/reports | tail -n +2 | awk '{print $1, $3, $4}' | sort | uniq -c
systemctl list-units --all 'candor-gh*' --no-legend | head
kill -INT $dpid; wait $dpid
grep -iE 'panic|error' /tmp/d.err | head -5
[ $fail -eq 0 ] && echo "WP24 GLASSHOUSE PASS" || { echo "WP24 GLASSHOUSE FAIL"; exit 1; }
