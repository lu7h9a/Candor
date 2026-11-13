#!/usr/bin/env bash
# WP23 Verify (VM only, root): run a harmless probe script through the full
# Glasshouse launcher and check the isolation properties of plan 6.2.
set -u
BIN=/opt/sysscope/bin
mkdir -p /usr/lib/sysusers.d && cp /dev/stdin /usr/lib/sysusers.d/sysscope.conf <<'CONF'
g sysscope -
g sysscope-act -
u sysscope-box - "SysScope Glasshouse sandbox" / /usr/sbin/nologin
CONF
systemd-sysusers /usr/lib/sysusers.d/sysscope.conf
id sysscope-box
cat > /tmp/box-probe.sh <<'PROBE'
#!/bin/sh
echo "ID: $(id)"
echo "ROOT: $(ls / | tr '\n' ' ')"
echo "PASSWD:"; cat /etc/passwd
echo "IP:"; /usr/sbin/ip -o addr 2>&1 || /usr/bin/ip -o addr 2>&1
echo "PS:"; ps aux
grep -E 'NoNewPrivs|Seccomp|Cap' /proc/self/status
echo "FDS: $(ls /proc/self/fd | tr '\n' ' ')"
echo "HOME: $(ls -a /home/victim | tr '\n' ' ')"
echo "SYS: $(ls /sys 2>&1 | head -1)"
PROBE
chmod +x /tmp/box-probe.sh
"$BIN/sysscope-glasshouse" run-local /tmp/box-probe.sh > /tmp/gh.out 2> /tmp/gh.err
rc=$?
cat /tmp/gh.err; cat /tmp/gh.out
fail=0
check() { if grep -qE "$2" /tmp/gh.out; then echo "OK   $1"; else echo "FAIL $1"; fail=1; fi; }
check "uid 1000"                    'ID: uid=1000\(victim\) gid=1000\(victim\)'
check "only the specified tree"     'ROOT: bin dev etc home lib (lib64 )?proc run sample sbin tmp usr var $'
check "synthetic passwd"            '^victim:x:1000:1000:Victim:/home/victim:/bin/sh$'
check "loopback only"               '^1: lo '
check "no other interfaces"         '^IP:$'
# Sample output is shown escaped (I10): a tab appears as \x09.
check "NoNewPrivs 1"                '^NoNewPrivs:\\x091$'
check "Seccomp 2"                   '^Seccomp:\\x092$'
check "CapEff zero"                 '^CapEff:\\x090+$'
check "CapPrm zero"                 '^CapPrm:\\x090+$'
check "CapBnd zero"                 '^CapBnd:\\x090+$'
check "CapInh zero"                 '^CapInh:\\x090+$'
check "CapAmb zero"                 '^CapAmb:\\x090+$'
check "decoys in home"              'HOME: .*\.ssh .*Documents'
check "no /sys"                     'SYS: ls: cannot access'
# Only box processes: ps shows PID 1 (bwrap) and the probe's own processes.
n=$(sed -n '/^PS:/,/^CapInh/p' /tmp/gh.out | grep -cE '^victim ')
[ "$n" -ge 2 ] && [ "$n" -le 4 ] && ! sed -n '/^PS:/,/^CapInh/p' /tmp/gh.out | grep -qvE '^(PS:|USER|victim |CapInh)' && echo "OK   only box processes ($n)" || { echo "FAIL only box processes ($n)"; fail=1; }
grep -qE '^2: ' /tmp/gh.out && { echo "FAIL a second network interface is visible"; fail=1; }
# fds: 0 1 2 plus ls's own directory fd (3).
grep -qE '^FDS: 0 1 2 3 $' /tmp/gh.out && echo "OK   fds 0-2 only (3 = ls itself)" || { echo "FAIL fds"; grep FDS /tmp/gh.out; fail=1; }
mount | grep -q /var/lib/sysscope/glasshouse && { echo "FAIL run dir still mounted"; fail=1; }
echo "run-local rc=$rc"
[ $fail -eq 0 ] && [ $rc -eq 0 ] && echo "WP23 GLASSHOUSE PASS" || { echo "WP23 GLASSHOUSE FAIL"; exit 1; }
