#!/usr/bin/env bash
# pkgtest.sh <distro> - plan WP30 Verify in one guest: install the package
# from target/packages, start the service, `candor status`, stop, remove,
# and a find-based check that nothing of Candor is left (account files
# changed by systemd-sysusers excepted, as for any package that adds a
# user). debian/ubuntu: .deb (then purge removes /etc/candor); fedora:
# .rpm; arch: makepkg from the tarball + PKGBUILD, pacman. With TARBALL=1
# any distro uses the tarball's install.sh / uninstall.sh --purge instead.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
source "$here/lib.sh"
d=${1:?distro}; pk="$repo/target/packages"
[ -d "$pk" ] || die "no target/packages: run make package first"
"$here/up.sh" "$d" >&2
tar -C "$pk" -cf - . | vm_ssh "$d" 'rm -rf ~/pkgs && mkdir ~/pkgs && tar -C ~/pkgs -xf -'
mode=$d; [ "${TARBALL:-0}" = 1 ] && mode=tarball
vm_ssh "$d" "sudo bash -s $mode" <<'GUEST'
set -euo pipefail
d=$1; cd "$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/pkgs"
snap() {
    find /usr /etc /var /opt -xdev 2>/dev/null | grep -Ev \
      '^/var/(log|cache|tmp|lib/(apt|dpkg|rpm|dnf|pacman|systemd|ucf|PackageKit|polkit-1|sss|man-db))(/|$)|^/etc/(ld\.so\.cache|passwd|group|shadow|gshadow|subuid|subgid)-?$|^/usr/share/(info/dir|mime|applications/mimeinfo\.cache|icons/hicolor/icon-theme\.cache)|^/var/lib/(dhcp|NetworkManager)|^/etc/(machine-id|resolv\.conf)' | sort
}
# Build tools the test itself needs come before the snapshot.
if [ "$d" = arch ]; then
    pacman -Syu --noconfirm --needed base-devel >/dev/null
    id builder >/dev/null 2>&1 || useradd -m builder
fi
snap > /tmp/before
case "$d" in
tarball)
    rm -rf /root/tb && mkdir /root/tb && tar -C /root/tb -xzf candor-*-x86_64.tar.gz
    # As if a normal user had unpacked it: install.sh must still install root-owned files.
    chown -R 65534:65534 /root/tb
    /root/tb/candor-*/install.sh > /tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; } ;;
debian12|ubuntu*)
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ./candor_*_amd64.deb > /tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; } ;;
fedora)
    dnf install -y -q ./candor-*.x86_64.rpm > /tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; } ;;
arch)
    id builder >/dev/null 2>&1 || useradd -m builder
    rm -rf /home/builder/pkg && mkdir /home/builder/pkg && cp PKGBUILD candor.install candor-*.tar.gz /home/builder/pkg/
    chown -R builder /home/builder/pkg
    su builder -c 'cd /home/builder/pkg && makepkg -f --nodeps' > /tmp/makepkg.log 2>&1 || { cat /tmp/makepkg.log; exit 1; }
    pacman -U --noconfirm /home/builder/pkg/candor-*.pkg.tar.* > /tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; } ;;
esac
if [ "$d" = tarball ]; then
    bad=$(find /usr/bin/candor* /usr/lib/systemd/system/candord* /usr/lib/sysusers.d/candor* /usr/share/doc/candor /usr/share/man/man*/candor* /etc/candor \! -user root 2>/dev/null || true)
    [ -z "$bad" ] && echo "OK   tarball files owned by root" || { echo "FAIL tarball files not owned by root:"; echo "$bad"; }
fi
grep -q "watches the processes of EVERY user" /tmp/install.log && echo "OK   post-install message shown" || { echo "FAIL post-install message"; cat /tmp/install.log; }
systemctl is-enabled candord.service >/dev/null 2>&1 && echo "FAIL service enabled by default" || echo "OK   service not enabled by default"
getent group candor >/dev/null && getent group candor-act >/dev/null && getent passwd candor-box >/dev/null && echo "OK   groups and sandbox user" || echo "FAIL sysusers"
systemctl start candord.service
for _ in $(seq 1 50); do [ -S /run/candor/candor.sock ] && break; sleep 0.2; done
st=$(stat -c '%a %U:%G' /run/candor/candor.sock)
[ "$st" = "660 root:candor" ] && echo "OK   socket $st" || echo "FAIL socket $st"
candor status > /tmp/status.txt 2>&1 && grep -q "processes:" /tmp/status.txt && echo "OK   candor status: $(grep -m1 processes: /tmp/status.txt)" || { echo "FAIL candor status"; cat /tmp/status.txt; journalctl -u candord --no-pager | tail -20; }
systemctl stop candord.service
case "$d" in
tarball) /root/tb/candor-*/uninstall.sh --purge >/dev/null ;;
debian12|ubuntu*) apt-get remove --autoremove -y -qq candor >/dev/null 2>&1 ;;
fedora) dnf remove -y -q candor >/dev/null ;;
arch) pacman -R --noconfirm candor >/dev/null ;;
esac
snap > /tmp/after
left=$(comm -13 /tmp/before /tmp/after)
case "$d" in
debian12|ubuntu*)
    [ "$(echo "$left" | grep -v '^/etc/candor' | grep -c .)" -eq 0 ] && [ -d /etc/candor ] \
        && echo "OK   remove: nothing left but /etc/candor (kept)" || { echo "FAIL remove left:"; echo "$left"; }
    apt-get purge --autoremove -y -qq candor >/dev/null 2>&1
    snap > /tmp/after
    left=$(comm -13 /tmp/before /tmp/after) ;;
esac
[ -z "$left" ] && echo "OK   nothing left after removal" || { echo "FAIL left after removal:"; echo "$left"; }
[ ! -e /run/candor ] && [ ! -e /var/lib/candor ] && echo "OK   socket and state dirs gone" || echo "FAIL socket/state dir left"
GUEST
