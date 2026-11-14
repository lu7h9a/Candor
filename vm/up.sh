#!/usr/bin/env bash
# up.sh <distro> - boot a clean dev guest (plan WP03).
# The guest disk is a throw-away overlay on the verified cloud image and QEMU
# runs with -snapshot, so nothing the guest does is kept. SSH is forwarded to
# 127.0.0.1 only. The cloud-init seed creates user "candor" with a fresh
# ephemeral key and the marker /etc/candor-test-vm (used by WP25 probes).
source "$(dirname "$0")/lib.sh"
d="${1:-}"; [ -n "$d" ] || die "usage: vm/up.sh <distro>"
distro_info "$d"
if vm_is_up "$d"; then echo "vm: $d already up (ssh port $SSH_PORT)"; exit 0; fi
preflight_kvm
fetch_image

st="${VM_STATE}/${d}"
rm -rf "$st"; mkdir -p "$st"; chmod 700 "$st"
ssh-keygen -q -t ed25519 -N '' -C "candor-vm-${d}" -f "${st}/id_ed25519"
pub=$(cat "${st}/id_ed25519.pub")

cat > "${st}/user-data" <<UD
#cloud-config
users:
  - name: ${VM_USER}
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - ${pub}
package_update: false
package_upgrade: false
write_files:
  - path: /etc/candor-test-vm
    content: "created by the Candor VM harness cloud-init; hostile probes may run here\n"
    permissions: "0644"
runcmd:
  - [sh, -c, "touch /run/candor-vm-ready"]
UD
printf 'instance-id: candor-%s-%s\nlocal-hostname: candor-%s\n' "$d" "$(date +%s)" "$d" > "${st}/meta-data"
genisoimage -quiet -output "${st}/seed.iso" -volid cidata -joliet -rock "${st}/user-data" "${st}/meta-data"

qemu-img create -q -f qcow2 -b "$IMG_FILE" -F qcow2 "${st}/overlay.qcow2" "${VM_DISK_GB}G"

qemu-system-x86_64 \
    -name "candor-${d}" -machine q35,accel=kvm -enable-kvm -cpu host \
    -m "$VM_MEM_MB" -smp "$VM_CPUS" \
    -drive "file=${st}/overlay.qcow2,if=virtio,format=qcow2" \
    -drive "file=${st}/seed.iso,if=virtio,format=raw,readonly=on" \
    -snapshot \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -display none -serial "file:${st}/console.log" \
    -pidfile "${st}/qemu.pid" -daemonize

echo "vm: $d booting (ssh 127.0.0.1:${SSH_PORT}); waiting for cloud-init" >&2
for _ in $(seq 1 120); do
    if vm_ssh "$d" 'test -f /run/candor-vm-ready' 2>/dev/null; then
        echo "vm: $d up"
        exit 0
    fi
    vm_is_up "$d" || die "qemu exited during boot; see ${st}/console.log"
    sleep 3
done
die "$d did not become ready in 6 minutes; see ${st}/console.log"
