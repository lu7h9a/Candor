#!/usr/bin/env bash
# matrix.sh <distro> - plan WP31 for one guest: install the package from
# target/packages, then run against the INSTALLED binaries the root itest
# subset (lifecycle, files, network, follow incl. the loss identity, the
# CLI export), one simulator per rule (rules_e2e), and the Glasshouse demo
# (or its correct "unavailable" answer). Results: target/matrix/<distro>.json
# (scripts/compat.py turns them into docs/COMPAT.md).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
source "$here/lib.sh"
d=${1:?distro}; pk="$repo/target/packages"
[ -d "$pk/itest" ] || die "no target/packages/itest: run make package first"
"$here/up.sh" "$d" >&2
tar -C "$pk" -cf - . | vm_ssh "$d" 'rm -rf ~/pkgs && mkdir ~/pkgs && tar -C ~/pkgs -xf -'
tar -C "$repo/testkit" -cf - --exclude=__pycache__ sim |
    vm_ssh "$d" 'sudo rm -rf /opt/candor && sudo mkdir -p /opt/candor && sudo tar --no-same-owner -C /opt/candor -xf -'
vm_ssh "$d" 'sudo tee /tmp/wp24.sh >/dev/null' < "$here/tests/wp24_glasshouse.sh"
mkdir -p "$repo/target/matrix"
vm_ssh "$d" "sudo bash -s $d" > "$repo/target/matrix/$d.json" <<'GUEST'
set -uo pipefail
d=$1; cd "$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/pkgs"
log=/root/matrix.log; : > $log
case "$d" in
debian12|ubuntu*) apt-get update -qq >>$log 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ./candor_*_amd64.deb strace python3 >>$log 2>&1 ;;
fedora) dnf install -y -q ./candor-*.x86_64.rpm strace python3 >>$log 2>&1 ;;
arch)
    pacman -Syu --noconfirm --needed base-devel strace python bubblewrap >>$log 2>&1
    id builder >/dev/null 2>&1 || useradd -m builder
    rm -rf /home/builder/pkg && mkdir /home/builder/pkg && cp PKGBUILD candor.install candor-*.tar.gz /home/builder/pkg/
    chown -R builder /home/builder/pkg
    su builder -c 'cd /home/builder/pkg && makepkg -f --nodeps' >>$log 2>&1
    pacman -U --noconfirm /home/builder/pkg/candor-*.pkg.tar.* >>$log 2>&1 ;;
esac
installed=$([ -x /usr/bin/candord ] && echo true || echo false)
# The tests run the installed binaries (symlinks; the daemon resolves its
# own path to /usr/bin and runs the installed, root-owned helper).
mkdir -p /opt/candor/bin
for b in candord candor candor-glasshouse; do ln -sf /usr/bin/$b /opt/candor/bin/$b; done
cp itest/* /opt/candor/bin/ && chown -R root:root /opt/candor && chmod -R go-w /opt/candor
touch /etc/candor-test-vm
export CANDOR_BIN_DIR=/opt/candor/bin CANDOR_SIM_DIR=/opt/candor/sim
dmesg_before=$(dmesg --level=err,warn | wc -l)
tests=/root/tests.txt; : > $tests
# Every test of a suite (from --list); a test is FAILED if the summary
# lists it, or if the binary ended without a summary (crash).
for s in lifecycle files network follow rules_e2e cli; do
    b=/opt/candor/bin/candor-itest-$s
    out=$("$b" --test-threads=1 2>&1); echo "$out" >> $log
    failed=$(echo "$out" | awk '/^failures:$/{n++; next} n==2 && /^    /{print $1} n==2 && /^test result/{exit}')
    summary=$(echo "$out" | grep -c '^test result:' || true)
    "$b" --list 2>/dev/null | sed -n 's/: test$//p' | while read -r t; do
        if [ "$summary" -eq 0 ] || echo "$failed" | grep -qx "$t"; then r=FAILED; else r=ok; fi
        echo "$s::$t $r" >> $tests
    done
done
# Glasshouse demo against the installed daemon (or the correct refusal).
bash /tmp/wp24.sh > /root/wp24.log 2>&1
gh=$(grep -oE 'WP24 (GLASSHOUSE PASS|GLASSHOUSE FAIL|UNAVAILABLE-CORRECTLY PASS|UNAVAILABLE FAIL)' /root/wp24.log | tail -1)
# Feature notes as users see them.
/usr/bin/candord --dev > /dev/null 2> /root/d.err &
dp=$!; for _ in $(seq 1 100); do grep -q serving /root/d.err && break; sleep 0.1; done
/usr/bin/candor status > /root/status.txt 2>&1
kill -TERM $dp; wait $dp 2>/dev/null
dmesg_new=$(dmesg --level=err,warn | tail -n +$((dmesg_before + 1)) | grep -Eic 'bpf|BUG|WARNING|RCU' || true)
python3 - "$d" "$installed" "$gh" "$dmesg_new" <<'PY'
import json, sys, platform
d, installed, gh, dm = sys.argv[1:]
tests = {}
for l in open("/root/tests.txt"):
    k, v = l.split()
    tests[k] = v
status = open("/root/status.txt").read().splitlines()
print(json.dumps({"distro": d, "kernel": platform.release(), "installed": installed == "true",
    "glasshouse": gh, "dmesg_bad_lines": int(dm or 0), "tests": tests,
    "features": next((l.split(":", 1)[1].strip() for l in status if l.startswith("features:")), ""),
    "unavailable": [l for l in status if "not available" in l],
    "install_log_tail": open("/root/matrix.log").read().splitlines()[-60:] if installed != "true" else [],
    "glasshouse_log_tail": open("/root/wp24.log").read().splitlines()[-40:],
    "pretty": open("/etc/os-release").read().split('PRETTY_NAME="')[1].split('"')[0]}))
PY
GUEST
# Full guest logs for diagnosis (target/matrix/<distro>.*.log).
for f in /root/matrix.log /root/wp24.log /tmp/cal.err /tmp/cal.out /tmp/d.err; do
    vm_ssh "$d" "sudo cat $f 2>/dev/null" > "$repo/target/matrix/$d.$(basename "$f").log" || true
done
"$here/down.sh" "$d" >/dev/null
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); t=r["tests"]; print(r["distro"], r["kernel"], "tests", sum(v=="ok" for v in t.values()), "/", len(t), "glasshouse:", r["glasshouse"], "unavailable:", r["unavailable"])' "$repo/target/matrix/$d.json"
