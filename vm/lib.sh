#!/usr/bin/env bash
# lib.sh - shared helpers for the SysScope dev VM harness (plan WP03).
# Sourced by up.sh, run.sh and down.sh. Everything the harness writes goes to
# ~/.cache/sysscope-vm (SKILL.md section 2 write allowlist).
set -euo pipefail

VM_CACHE="${HOME}/.cache/sysscope-vm"
VM_IMAGES="${VM_CACHE}/images"
VM_STATE="${VM_CACHE}/state"
VM_MEM_MB="${VM_MEM_MB:-2048}"
VM_CPUS="${VM_CPUS:-2}"
VM_DISK_GB="${VM_DISK_GB:-12}"
VM_USER=sysscope

die() { echo "vm: $*" >&2; exit 1; }

# distro_info <distro> sets IMG_URL SUM_URL SUM_ALGO IMG_FILE SSH_PORT.
# Checksums come from the same official origin over HTTPS.
distro_info() {
    case "$1" in
        debian12)
            IMG_URL=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2
            SUM_URL=https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS
            SUM_ALGO=sha512; SSH_PORT=2221 ;;
        ubuntu2204)
            IMG_URL=https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
            SUM_URL=https://cloud-images.ubuntu.com/jammy/current/SHA256SUMS
            SUM_ALGO=sha256; SSH_PORT=2222 ;;
        ubuntu2404)
            IMG_URL=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
            SUM_URL=https://cloud-images.ubuntu.com/noble/current/SHA256SUMS
            SUM_ALGO=sha256; SSH_PORT=2223 ;;
        fedora)
            # "Current" Fedora at the time of writing; bump both lines together.
            IMG_URL=https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-45-1.4.x86_64.qcow2
            SUM_URL=https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-45-1.4-x86_64-CHECKSUM
            SUM_ALGO=sha256; SSH_PORT=2224 ;;
        arch)
            IMG_URL=https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2
            SUM_URL=https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2.SHA256
            SUM_ALGO=sha256; SSH_PORT=2225 ;;
        *) die "unknown distro '$1' (debian12 ubuntu2204 ubuntu2404 fedora arch)" ;;
    esac
    IMG_FILE="${VM_IMAGES}/$(basename "$IMG_URL")"
}

ALL_DISTROS=(debian12 ubuntu2204 ubuntu2404 fedora arch)

# Refuse to start unless QEMU can use KVM and VirtualBox is idle (E2).
preflight_kvm() {
    [ -r /dev/kvm ] && [ -w /dev/kvm ] || die "/dev/kvm is not usable by $(id -un) (escalate E2)"
    if command -v VBoxManage >/dev/null 2>&1; then
        local running
        running=$(VBoxManage list runningvms 2>/dev/null || true)
        [ -z "$running" ] || die "a VirtualBox VM is running; refusing to start QEMU (escalate E2): $running"
    fi
    local avail_mb
    avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
    # E5 line: 6 GB (decimal, = 5722 MiB) available, and at least guest RAM + 2 GiB.
    local need=$((VM_MEM_MB + 2048)); [ "$need" -ge 5722 ] || need=5722
    [ "$avail_mb" -ge "$need" ] || die "only ${avail_mb} MiB RAM available; need ${need} (escalate E5)"
}

# Download the image once and verify it against the published checksum.
fetch_image() {
    mkdir -p "$VM_IMAGES"
    local sums="${IMG_FILE}.sums" name expected actual
    name=$(basename "$IMG_URL")
    curl -sSfL --proto '=https' "$SUM_URL" -o "$sums"
    # Formats differ: "<hash>  name", "<hash> *name", Fedora "SHA256 (name) = <hash>".
    expected=$(awk -v n="$name" '
        $2 == n || $2 == "*" n { print $1; exit }
        $1 ~ /^SHA(256|512)$/ && $2 == "(" n ")" { print $4; exit }' "$sums")
    [ -n "$expected" ] || die "no checksum for $name in $SUM_URL"
    if [ -f "$IMG_FILE" ]; then
        actual=$(${SUM_ALGO}sum "$IMG_FILE" | awk '{print $1}')
        [ "$actual" = "$expected" ] && return 0
        echo "vm: cached $name does not match the published checksum; downloading again" >&2
    fi
    echo "vm: downloading $IMG_URL" >&2
    curl -sSfL --proto '=https' "$IMG_URL" -o "${IMG_FILE}.part"
    actual=$(${SUM_ALGO}sum "${IMG_FILE}.part" | awk '{print $1}')
    [ "$actual" = "$expected" ] || { rm -f "${IMG_FILE}.part"; die "checksum mismatch for $name"; }
    mv "${IMG_FILE}.part" "$IMG_FILE"
}

ssh_opts() {
    local d="$1"
    echo "-i ${VM_STATE}/${d}/id_ed25519 -p ${SSH_PORT} -o StrictHostKeyChecking=no \
-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=yes"
}

vm_ssh() { # vm_ssh <distro> <command...>
    local d="$1"; shift
    distro_info "$d"
    # shellcheck disable=SC2046
    ssh $(ssh_opts "$d") "${VM_USER}@127.0.0.1" "$@"
}

vm_is_up() {
    local pidf="${VM_STATE}/$1/qemu.pid"
    [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null
}
