#!/bin/sh
# /usr/local/sbin/sysscope-detonate (detonation guest only, plan 6.6 step 3).
# Started at boot by sysscope-detonate.service when the read-only sample ISO
# (label SYSSCOPESAMPLE) is attached: extracts the sample from its password-
# protected zip, runs it in Glasshouse, writes the JSON report to the second
# serial port (/dev/ttyS1) between marker lines, and powers the guest off.
# The guest has no network device and runs on a -snapshot disk.
out=/dev/ttyS1
stty -F "$out" raw -echo 2>/dev/null || true  # no \n -> \r\n translation
say() { printf '%s\n' "$*" > /dev/ttyS0; }
finish() {
    { echo "SYSSCOPE-REPORT-BEGIN"; cat "$1"; echo; echo "SYSSCOPE-REPORT-END"; } > "$out"
    sync; poweroff -f
}
mkdir -p /mnt/sample /root/sample
if ! mount -o ro /dev/disk/by-label/SYSSCOPESAMPLE /mnt/sample; then
    echo '{"error":"no sample disc"}' > /root/err.json; finish /root/err.json
fi
timeout=$(tr -cd 0-9 < /mnt/sample/timeout); [ -n "$timeout" ] || timeout=60
name=$(python3 - <<'PY'
import os, sys, zipfile
pw = open("/mnt/sample/password", "rb").read().rstrip(b"\r\n")
z = zipfile.ZipFile("/mnt/sample/sample.zip")
files = [i for i in z.infolist() if not i.is_dir()]
if len(files) != 1:
    sys.exit("the archive must hold exactly one file")
i = files[0]
name = os.path.basename(i.filename) or "sample"
with z.open(i, pwd=pw) as src, open("/root/sample/" + name, "wb") as dst:
    while True:
        b = src.read(1 << 20)
        if not b:
            break
        dst.write(b)
print(name)
PY
) || { echo '{"error":"the archive could not be extracted (wrong password, not a ZipCrypto zip, or more than one file)"}' > /root/err.json; finish /root/err.json; }
say "sysscope-detonate: running $name for ${timeout}s"
/opt/sysscope/bin/sysscoped --dev > /root/sysscoped.log 2>&1 &
for _ in $(seq 1 100); do [ -S /run/sysscope-dev/sysscope.sock ] && break; sleep 0.1; done
sleep 1
if /opt/sysscope/bin/sysscope --json glasshouse run --timeout "$timeout" "/root/sample/$name" > /root/report.json 2> /root/run.err; then
    finish /root/report.json
fi
python3 -c 'import json,sys;print(json.dumps({"error":"the Glasshouse run failed","detail":open("/root/run.err").read()[-2000:]}))' > /root/err.json
finish /root/err.json
