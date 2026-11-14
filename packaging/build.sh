#!/usr/bin/env bash
# build.sh VERSION - runs as root INSIDE the ubuntu2204 build VM (oldest
# supported glibc, plan WP30) on the source tree unpacked at /root/src.
# Builds the release binaries, stages them (stage.sh) and writes to
# /root/out: the .deb, the .rpm, the tarball, the Arch PKGBUILD and the
# lintian/rpmlint reports.
set -euo pipefail
ver=${1:?VERSION}
src=/root/src; out=/root/out; work=/root/pkgwork
rm -rf "$out" "$work"; mkdir -p "$out" "$work"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential clang llvm libelf-dev zlib1g-dev libzstd-dev pkg-config \
    libxkbcommon-dev libwayland-dev libx11-dev libxcursor-dev libxi-dev libxrandr-dev \
    libfontconfig-dev dpkg-dev fakeroot rpm lintian rpmlint curl >/dev/null
if [ ! -x /root/.cargo/bin/cargo ]; then
    # The official rustup installer (plan section 2).
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none >/dev/null
fi
export PATH=/root/.cargo/bin:$PATH
cd "$src"
cargo build --release --locked -p sysscoped -p sysscope-cli -p sysscope-gui -p sysscope-glasshouse 2>&1 | tail -3
bin="$src/target/release"
echo "glibc needed: $(objdump -T "$bin"/sysscoped "$bin"/sysscope "$bin"/sysscope-gui "$bin"/sysscope-glasshouse | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1)"
ldd "$bin/sysscoped" | grep -q libbpf && { echo "libbpf is linked dynamically"; exit 1; } || echo "libbpf: static"

stage="$work/stage"; packaging/stage.sh "$bin" "$stage"

# --- .deb -------------------------------------------------------------------
deb="$work/deb"; cp -a "$stage" "$deb"; mkdir -p "$deb/DEBIAN"
install -m 0755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm "$deb/DEBIAN/"
(cd "$deb" && find etc -type f | sed 's|^|/|') > "$deb/DEBIAN/conffiles"
cat > "$deb/usr/share/doc/sysscope/copyright" <<COPY
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: sysscope
Source: https://github.com/lu7h9a/sysscope

Files: *
Copyright: 2026 SysScope authors
License: MIT

License: MIT
$(sed 's/^$/./; s/^/ /' LICENSE)
COPY
printf 'sysscope (%s-1) unstable; urgency=medium\n\n  * Release %s.\n\n -- SysScope <noreply@github.com>  %s\n' \
    "$ver" "$ver" "$(date -R)" | gzip -9n > "$deb/usr/share/doc/sysscope/changelog.Debian.gz"
size=$(du -sk --exclude=DEBIAN "$deb" | cut -f1)
cat > "$deb/DEBIAN/control" <<CTRL
Package: sysscope
Version: $ver-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: SysScope <noreply@github.com>
Installed-Size: $size
Depends: libc6 (>= 2.35), libelf1, zlib1g, libzstd1, systemd
Recommends: bubblewrap
Homepage: https://github.com/lu7h9a/sysscope
Description: process monitor that explains what programs do (eBPF)
 SysScope shows what every program on the computer is doing (programs
 started, files opened, network connections), flags suspicious behaviour
 with plain-language explanations, and can run a program in a sandbox to
 show what it touches. The daemon watches the processes of all users.
CTRL
dpkg-deb --root-owner-group -Zxz --build "$deb" "$out/sysscope_${ver}-1_amd64.deb" >/dev/null

# --- .rpm -------------------------------------------------------------------
rpmbuild -bb --quiet --define "_topdir $work/rpm" --define "_stage $stage" \
    --define "_version $ver" packaging/rpm/sysscope.spec
cp "$work"/rpm/RPMS/x86_64/sysscope-"$ver"-1.x86_64.rpm "$out/"

# --- tarball + Arch PKGBUILD -------------------------------------------------
t="sysscope-${ver}-x86_64"; tdir="$work/$t"; mkdir -p "$tdir"
cp -a "$stage" "$tdir/root"
install -m 0755 packaging/tarball/install.sh packaging/tarball/uninstall.sh "$tdir/"
cp README.md LICENSE "$tdir/"
(cd "$tdir/root" && find . ! -type d | sed 's|^\.||' | sort) > "$tdir/MANIFEST"
tar -C "$work" --owner=0 --group=0 --numeric-owner -czf "$out/$t.tar.gz" "$t"
sha=$(sha256sum "$out/$t.tar.gz" | cut -d' ' -f1)
sed "s/@VERSION@/$ver/; s/@SHA256@/$sha/" packaging/arch/PKGBUILD > "$out/PKGBUILD"
cp packaging/arch/sysscope.install "$out/"

# --- lint ---------------------------------------------------------------------
lintian --no-tag-display-limit "$out/sysscope_${ver}-1_amd64.deb" > "$out/lintian.txt" 2>&1 || true
rpmlint "$out/sysscope-$ver-1.x86_64.rpm" > "$out/rpmlint.txt" 2>&1 || true
(cd "$out" && sha256sum ./*.deb ./*.rpm ./*.tar.gz > SHA256SUMS)
echo "lintian errors: $(grep -c '^E:' "$out/lintian.txt" || true), warnings: $(grep -c '^W:' "$out/lintian.txt" || true)"
echo "rpmlint: $(tail -1 "$out/rpmlint.txt")"
ls -l "$out"
