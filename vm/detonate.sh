#!/usr/bin/env bash
# detonate.sh <archive.zip> <password> [timeout] - runs ONE sample inside a
# disposable detonation guest (plan 6.6, docs/REAL_SAMPLES.md). Never on the host.
#   - the archive goes in a read-only ISO; the guest disk is -snapshot (all
#     writes discarded); -nic none (no network device); -nodefaults (no USB,
#     no extra devices); no shared folders; serial port 2 -> a host file;
#   - QEMU is killed at timeout + 60 s regardless;
#   - the report is read from the serial file as untrusted text: at most
#     64 MiB, strict JSON, shown escaped by `candor glasshouse report`.
# Refuses if QEMU cannot use KVM, if a VirtualBox VM is running, or if its
# own QEMU command line holds any -nic/-netdev/-net other than "-nic none"
# (DETONATE_QEMU_EXTRA adds options and exists only so this refusal can be
# tested).
source "$(dirname "$0")/lib.sh"
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
archive="${1:-}"; password="${2:-}"; timeout_s="${3:-60}"
[ -f "$archive" ] && [ -n "$password" ] || die "usage: vm/detonate.sh <archive.zip> <password> [timeout 1-600]"
[[ "$timeout_s" =~ ^[0-9]+$ ]] && [ "$timeout_s" -ge 1 ] && [ "$timeout_s" -le 600 ] || die "timeout must be 1-600 seconds"
img="${VM_CACHE}/detonation/detonation.qcow2"
[ -f "$img" ] || die "no detonation image; run vm/build-detonation-image.sh first"
VM_MEM_MB=2048 preflight_kvm
stamp=$(date +%Y%m%d-%H%M%S)
run="${VM_CACHE}/detonate/${stamp}"; mkdir -p "$run/iso"; chmod 700 "${VM_CACHE}/detonate" "$run"
cp "$archive" "$run/iso/sample.zip"
printf '%s\n' "$password" > "$run/iso/password"
printf '%s\n' "$timeout_s" > "$run/iso/timeout"
genisoimage -quiet -output "$run/sample.iso" -volid CANDORSAMPLE -rock "$run/iso"
rm -rf "$run/iso"
args=(qemu-system-x86_64 -name candor-detonation -nodefaults -no-user-config
      -machine q35,accel=kvm -enable-kvm -cpu host -m 2048 -smp 2
      -drive "file=${img},if=virtio,format=qcow2" -snapshot
      -drive "file=${run}/sample.iso,media=cdrom,readonly=on"
      -nic none -display none
      -serial "file:${run}/console.log" -serial "file:${run}/report.serial")
# shellcheck disable=SC2206
[ -n "${DETONATE_QEMU_EXTRA:-}" ] && args+=(${DETONATE_QEMU_EXTRA})
# Check the command line we are about to run, not our intentions.
nets=0; prev=""
for a in "${args[@]}"; do
    case "$prev" in
        -nic) [ "$a" = none ] || die "refusing: network option '-nic $a' in the QEMU command line" ;;
        -netdev|-net) die "refusing: '$prev $a' in the QEMU command line" ;;
    esac
    [ "$a" = -nic ] && nets=$((nets + 1))
    prev="$a"
done
for a in "${args[@]}"; do case "$a" in *virtio-net*|*e1000*|*rtl8139*|*usb*) die "refusing: device '$a'" ;; esac; done
[ "$nets" -eq 1 ] || die "refusing: expected exactly one '-nic none'"
printf '%q ' "${args[@]}" > "$run/qemu-cmdline.txt"
{
    echo "Candor detonation report header"
    echo "date: $(date -Is)"
    echo "archive: $(basename "$archive") sha256 $(sha256sum "$archive" | cut -d' ' -f1)"
    echo "timeout: ${timeout_s}s (QEMU killed at $((timeout_s + 60))s)"
    echo "qemu: $(cat "$run/qemu-cmdline.txt")"
} > "$run/report-header.txt"
echo "detonate: booting the detonation guest (no network, disk changes discarded)"
set +e
timeout --signal=KILL "$((timeout_s + 60))" "${args[@]}"
rc=$?
set -e
[ $rc -eq 137 ] && echo "detonate: QEMU was killed at the time limit"
# Untrusted text from the guest: capped, then only the marked block, strictly parsed.
head -c $((64 << 20)) "$run/report.serial" > "$run/report.capped" 2>/dev/null || true
python3 - "$run/report.capped" "$run/report.json" <<'PY'
import json, sys
# A serial tty may turn "\n" into "\r\n"; raw newlines cannot occur inside
# JSON strings, so this changes only whitespace.
data = open(sys.argv[1], "rb").read().replace(b"\r\n", b"\n")
b, e = data.find(b"CANDOR-REPORT-BEGIN\n"), data.rfind(b"\nCANDOR-REPORT-END")
if b < 0 or e < b:
    sys.exit("detonate: no complete report on the serial port")
body = data[b + len(b"CANDOR-REPORT-BEGIN\n"):e].strip()
obj = json.loads(body)
if "error" in obj:
    sys.exit("detonate: the guest reported an error: %s" % json.dumps(obj)[:2000])
open(sys.argv[2], "wb").write(body + b"\n")
PY
[ -f "$run/report.json" ] || die "no report (see $run/console.log)"
rm -f "$run/report.capped" "$run/sample.iso"
cat "$run/report-header.txt"
echo
"$repo/target/release/candor" glasshouse report "$run/report.json"
echo
echo "detonate: report files: $run/report-header.txt and $run/report.json"
