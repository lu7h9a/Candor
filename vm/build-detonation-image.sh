#!/usr/bin/env bash
# build-detonation-image.sh - builds the detonation guest disk once (plan
# 6.6): Debian 12 cloud image + bubblewrap + SysScope release binaries +
# the autorun unit (vm/detonation/autorun.sh). The build boot has network
# (to install bubblewrap) and NO sample; the finished disk is flattened to
# ~/.cache/sysscope-vm/detonation/detonation.qcow2 and is only ever booted
# by vm/detonate.sh with -snapshot and -nic none. Re-run after `make release`
# to refresh the binaries.
source "$(dirname "$0")/lib.sh"
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
distro_info debian12
preflight_kvm
fetch_image
dir="${VM_CACHE}/detonation"; st="${dir}/build"
rm -rf "$st"; mkdir -p "$st"; chmod 700 "$dir" "$st"
port=2229
ssh-keygen -q -t ed25519 -N '' -C sysscope-detonation-build -f "${st}/id_ed25519"
cat > "${st}/user-data" <<UD
#cloud-config
users:
  - name: ${VM_USER}
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "${st}/id_ed25519.pub")
write_files:
  - path: /etc/sysscope-test-vm
    content: "SysScope detonation guest (built by vm/build-detonation-image.sh)\n"
runcmd:
  - [sh, -c, "touch /run/sysscope-vm-ready"]
UD
printf 'instance-id: sysscope-detonation-build-%s\nlocal-hostname: sysscope-detonation\n' "$(date +%s)" > "${st}/meta-data"
genisoimage -quiet -output "${st}/seed.iso" -volid cidata -joliet -rock "${st}/user-data" "${st}/meta-data"
qemu-img create -q -f qcow2 -b "$IMG_FILE" -F qcow2 "${st}/disk.qcow2" 8G
qemu-system-x86_64 -name sysscope-detonation-build -machine q35,accel=kvm -enable-kvm -cpu host \
    -m 2048 -smp 2 \
    -drive "file=${st}/disk.qcow2,if=virtio,format=qcow2" \
    -drive "file=${st}/seed.iso,if=virtio,format=raw,readonly=on" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${port}-:22" \
    -display none -serial "file:${st}/console.log" -pidfile "${st}/qemu.pid" -daemonize
s() { ssh -i "${st}/id_ed25519" -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=yes "${VM_USER}@127.0.0.1" "$@"; }
ok=0
for _ in $(seq 1 120); do s 'test -f /run/sysscope-vm-ready' 2>/dev/null && { ok=1; break; }; sleep 3; done
[ $ok -eq 1 ] || { kill "$(cat "${st}/qemu.pid")"; die "build guest did not come up; see ${st}/console.log"; }
tar -C "$repo/target/release" -cf - sysscoped sysscope sysscope-glasshouse | s 'sudo mkdir -p /opt/sysscope/bin && sudo tar -C /opt/sysscope/bin -xf -'
s 'sudo tee /usr/local/sbin/sysscope-detonate > /dev/null && sudo chmod 755 /usr/local/sbin/sysscope-detonate' < "$here/detonation/autorun.sh"
s 'sudo bash -s' <<'GUEST'
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update && apt-get -qq install -y bubblewrap > /dev/null
mkdir -p /usr/lib/sysusers.d
printf 'g sysscope -\ng sysscope-act -\nu sysscope-box - "SysScope Glasshouse sandbox" / /usr/sbin/nologin\n' > /usr/lib/sysusers.d/sysscope.conf
systemd-sysusers /usr/lib/sysusers.d/sysscope.conf
cat > /etc/systemd/system/sysscope-detonate.service <<'UNIT'
[Unit]
Description=SysScope detonation run (sample disc attached)
ConditionPathExists=/dev/disk/by-label/SYSSCOPESAMPLE
After=local-fs.target systemd-udev-settle.service
Wants=systemd-udev-settle.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sysscope-detonate
[Install]
WantedBy=multi-user.target
UNIT
systemctl enable sysscope-detonate.service
/opt/sysscope/bin/sysscope-glasshouse availability
# No cloud-init, ssh or build key in the finished image.
touch /etc/cloud/cloud-init.disabled
systemctl disable ssh.service 2>/dev/null || true
rm -f /home/sysscope/.ssh/authorized_keys
apt-get -qq clean
sync
# Power off from here (the build key is gone); the host waits for QEMU.
systemd-run --on-active=2 --timer-property=AccuracySec=100ms systemctl poweroff
GUEST
for _ in $(seq 1 60); do [ -f "${st}/qemu.pid" ] && kill -0 "$(cat "${st}/qemu.pid")" 2>/dev/null || break; sleep 1; done
if [ -f "${st}/qemu.pid" ] && kill -0 "$(cat "${st}/qemu.pid")" 2>/dev/null; then
    kill "$(cat "${st}/qemu.pid")"; die "the build guest did not power off cleanly; image not updated"
fi
qemu-img convert -O qcow2 "${st}/disk.qcow2" "${dir}/detonation.qcow2.new"
mv "${dir}/detonation.qcow2.new" "${dir}/detonation.qcow2"
chmod 600 "${dir}/detonation.qcow2"
rm -rf "$st"
echo "detonation image: ${dir}/detonation.qcow2"
