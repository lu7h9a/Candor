#!/usr/bin/env bash
# run_all.sh - WP25 adversarial suite, run as root INSIDE A TEST VM ONLY
# (vm/hostile.sh embeds it with hostile.py and starts it).
# Refuses unless /etc/sysscope-test-vm exists (created only by the VM
# harness's cloud-init) AND DMI reports a QEMU machine.
# Writes the current probe to /tmp/hostile.phase (vm/hostile.sh times SSH
# against it) and /tmp/hostile.done at the end.
set -u
if [ ! -f /etc/sysscope-test-vm ] || ! grep -q QEMU /sys/class/dmi/id/sys_vendor 2>/dev/null; then
    echo "REFUSED: run_all.sh runs only in a SysScope test VM (marker + QEMU DMI)"; exit 3
fi
BIN=/opt/sysscope/bin
H=/tmp/hostile.py
rm -f /tmp/hostile.done /var/tmp/core-caught-*
echo setup > /tmp/hostile.phase
mkdir -p /usr/lib/sysusers.d && printf 'g sysscope -\ng sysscope-act -\nu sysscope-box - "SysScope Glasshouse sandbox" / /usr/sbin/nologin\n' > /usr/lib/sysusers.d/sysscope.conf
systemd-sysusers /usr/lib/sysusers.d/sysscope.conf
"$BIN/sysscoped" --dev > /tmp/d.out 2> /tmp/d.err &
dpid=$!
for _ in $(seq 1 100); do [ -S /run/sysscope-dev/sysscope.sock ] && break; sleep 0.1; done
sleep 1
finish() { kill -INT $dpid 2>/dev/null; wait $dpid 2>/dev/null; echo "$1" > /tmp/hostile.done; }

if ! why=$("$BIN/sysscope-glasshouse" availability); then
    echo "Glasshouse $why"
    "$BIN/sysscope" glasshouse run --timeout 10 "$H" syscalls > /dev/null 2> /tmp/u.err; rc=$?
    cat /tmp/u.err
    if [ $rc -ne 0 ] && grep -q "Glasshouse is not available on this system" /tmp/u.err; then
        echo "HOSTILE UNAVAILABLE-CORRECTLY PASS (no box can start here, so there is nothing to attack)"
        finish pass; exit 0
    fi
    echo "HOSTILE UNAVAILABLE FAIL"; finish fail; exit 1
fi

# Things outside the box that probes try to reach.
python3 -c "import socket,time;s=socket.socket(socket.AF_UNIX);s.bind('\0sysscope-hostile-abstract');s.listen();time.sleep(3600)" &
lpid=$!
mkdir -p /tmp/.X11-unix && python3 -c "import socket,time,os;p='/tmp/.X11-unix/X0';os.path.exists(p) and os.unlink(p);s=socket.socket(socket.AF_UNIX);s.bind(p);os.chmod(p,0o777);s.listen();time.sleep(3600)" &
xpid=$!
# A host core handler that records any invocation (restored at the end).
old_core=$(cat /proc/sys/kernel/core_pattern)
cat > /usr/local/sbin/sysscope-core-catcher <<'SH'
#!/bin/sh
echo "$1 $2" >> /var/tmp/core-caught-$1
cat > /dev/null
SH
chmod 755 /usr/local/sbin/sysscope-core-catcher
echo '|/usr/local/sbin/sysscope-core-catcher %p %u' > /proc/sys/kernel/core_pattern

escaped=0; contained=0
results=""
judge() { # probe json -> prints the verdict from ~/VERDICT.txt in the report
    python3 - "$1" <<'PY'
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except Exception as e:
    print("NO-REPORT (%s)" % e); sys.exit()
v = [c for c in r["created"] if c["path"] == "/home/victim/VERDICT.txt"]
pre = v[0].get("preview") if v else None
first = pre.split("\\x0A")[0] if pre else "NO-VERDICT"
print(first)
PY
}
report_field() { python3 -c "import json,sys;r=json.load(open(sys.argv[1]));print(eval(sys.argv[2]))" "$1" "$2" 2>/dev/null; }
leftovers() {
    for _ in $(seq 1 20); do
        if ! pgrep -u sysscope-box > /dev/null && [ -z "$(systemctl list-units --all 'sysscope-gh*' --no-legend --plain)" ] \
            && ! mount | grep -q /var/lib/sysscope/glasshouse/; then
            echo none; return
        fi
        sleep 0.5
    done
    echo "procs=$(pgrep -u sysscope-box | wc -l) units=$(systemctl list-units --all 'sysscope-gh*' --no-legend --plain | wc -l) mounts=$(mount | grep -c /var/lib/sysscope/glasshouse/)"
}

for spec in syscalls:30 hostfiles:30 procs:30 network:30 sockets:30 setuid:30 userns:30 tiocsti:30 \
            forkbomb:20 membomb:20 cpuhog:20 diskfill:60 flood:30 tamper:30 coredump:30 torture:180 \
            persist:30 fds:30 detect:30 sidechannel:30; do
    p=${spec%%:*}; t=${spec#*:}
    echo "$p" > /tmp/hostile.phase
    free_before=$(df --output=avail -m / | tail -1)
    start=$(date +%s)
    "$BIN/sysscope" --json glasshouse run --timeout "$t" "$H" "$p" > "/tmp/h-$p.json" 2> "/tmp/h-$p.err"
    rc=$?
    took=$(( $(date +%s) - start ))
    verdict=$(judge "/tmp/h-$p.json")
    extra=""
    left=$(leftovers)
    [ "$left" = none ] || { verdict="ESCAPED:left behind after the run: $left"; }
    case $p in
        forkbomb|membomb|cpuhog)
            to=$(report_field "/tmp/h-$p.json" 'r["timed_out"] or r["exit_code"] != 0')
            [ "$to" = True ] || verdict="ESCAPED:the run was not stopped (rc=$rc)"
            extra="ended: $(report_field "/tmp/h-$p.json" '("timeout" if r["timed_out"] else "exit %s %s" % (r["exit_code"], r["notes"]))')" ;;
        diskfill)
            free_after=$(df --output=avail -m / | tail -1)
            [ $((free_before - free_after)) -lt 50 ] || verdict="ESCAPED:host disk shrank by $((free_before - free_after)) MiB"
            extra="host / free: $free_before -> $free_after MiB" ;;
        flood)
            b=$(report_field "/tmp/h-$p.json" 'r["loss"]["budget"]')
            r8=$(report_field "/tmp/h-$p.json" '"R008" in {f["rule"] for f in r["findings"]}')
            "$BIN/sysscope" status > /dev/null || verdict="ESCAPED:daemon unhealthy after the flood"
            { [ "${b:-0}" -gt 0 ] && [ "$r8" = True ]; } || verdict="ESCAPED:flood not reported (budget drops ${b:-?}, R008 $r8)"
            kh=$(report_field "/tmp/h-$p.json" '[d["states"] for d in r["decoys"] if d["path"].endswith("/.ssh/known_hosts")][0]')
            case $kh in *read*) ;; *) verdict="ESCAPED:a box child's decoy read after the flood is missing (known_hosts $kh)" ;; esac
            extra="budget drops counted: $b, R008: $r8, child read after flood: $kh, notes: $(report_field "/tmp/h-$p.json" '"; ".join(r["notes"])')" ;;
        coredump)
            if ls /var/tmp/core-caught-* > /dev/null 2>&1; then
                verdict="ESCAPED:the host core handler ran for a box process ($(cat /var/tmp/core-caught-* | tr '\n' ' '))"
            fi
            extra="core handler invocations: $(ls /var/tmp/core-caught-* 2>/dev/null | wc -l)" ;;
        torture)
            "$BIN/sysscope" glasshouse report "/tmp/h-$p.json" > /tmp/h-torture.txt 2>&1
            ctl=$(LC_ALL=C grep -c -P '[\x00-\x08\x0b-\x1f\x7f]' /tmp/h-torture.txt)
            [ "$ctl" -eq 0 ] || verdict="ESCAPED:$ctl report lines contain raw control bytes"
            LC_ALL=C grep -q -P '[\x00-\x08\x0b-\x1f\x7f]' "/tmp/h-$p.json" && verdict="ESCAPED:raw control bytes in the JSON report"
            # C1 controls and bidi/zero-width characters (UTF-8) in either
            # output, or in the saved report.
            for f in /tmp/h-torture.txt "/tmp/h-$p.json" /var/lib/sysscope/reports/*.json; do
                LC_ALL=C grep -q -P '\xc2[\x80-\x9f]|\xe2\x80[\x8b-\x8f\xaa-\xae]|\xe2\x81[\xa6-\xa9]' "$f" && verdict="ESCAPED:C1/bidi characters unescaped in $f"
            done
            unread=$(report_field "/tmp/h-$p.json" '[d["path"] for d in r["decoys"] if "deleted" in d["states"] or "modified" in d["states"]]')
            [ "$unread" = "[]" ] || verdict="ESCAPED:decoys the sample made unreadable were misreported: $unread"
            [ "$took" -le $((t + 90)) ] || verdict="ESCAPED:run + differ took $took s"
            extra="took ${took}s; notes: $(report_field "/tmp/h-$p.json" '"; ".join(r["notes"])'); created listed: $(report_field "/tmp/h-$p.json" 'len(r["created"])')" ;;
    esac
    case $verdict in
        CONTAINED*) contained=$((contained + 1)) ;;
        *) escaped=$((escaped + 1)) ;;
    esac
    line="PROBE $p: $verdict (rc=$rc, ${took}s) $extra"
    echo "$line"
    grep -v '^Glasshouse is a behaviour' "/tmp/h-$p.err" | grep -iE 'fail|error' | head -2 | sed 's/^/    /'
    results="$results$line"$'\n'
done
echo "$old_core" > /proc/sys/kernel/core_pattern
kill $lpid $xpid 2>/dev/null
echo "== summary"
printf '%s' "$results" | cut -c1-160
echo "HOSTILE SUMMARY: $contained contained, $escaped escaped"
echo "dmesg (box-related, last lines):"; dmesg | grep -iE 'oom|segfault|core|sysscope' | tail -5
if [ $escaped -eq 0 ]; then echo "HOSTILE PASS"; finish pass; exit 0; fi
echo "HOSTILE FAIL"; finish fail; exit 1
