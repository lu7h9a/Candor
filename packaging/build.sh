#!/usr/bin/env bash
# build.sh VERSION - builds every package on the oldest supported glibc
# (ubuntu 22.04, plan WP30): inside the build VM (vm/package.sh, as root, on
# /root/src) or on a GitHub ubuntu-22.04 runner (release workflow, WP32).
# Builds the release binaries, stages them (stage.sh) and writes to OUT:
# the .deb, the .rpm, the tarball, the Arch PKGBUILD, SHA256SUMS and the
# lintian/rpmlint reports.
# Environment: CANDOR_SRC (default /root/src), CANDOR_OUT (default
# /root/out), CANDOR_SKIP_SETUP=1 (packages and Rust already installed),
# CANDOR_ITEST=1 (also the root itest binaries for the distro matrix),
# CANDOR_GIT_COMMIT (for --version; no .git in the VM's source copy).
set -euo pipefail
ver=${1:?VERSION}
src=${CANDOR_SRC:-/root/src}; out=${CANDOR_OUT:-/root/out}; work="$out.work"
rm -rf "$out" "$work"; mkdir -p "$out" "$work"
if [ "${CANDOR_SKIP_SETUP:-0}" != 1 ]; then
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential clang llvm libelf-dev zlib1g-dev libzstd-dev pkg-config \
    libxkbcommon-dev libwayland-dev libx11-dev libxcursor-dev libxi-dev libxrandr-dev \
    libfontconfig-dev dpkg-dev fakeroot rpm lintian rpmlint curl >/dev/null
if [ ! -x /root/.cargo/bin/cargo ]; then
    # The official rustup installer (plan section 2).
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none >/dev/null
fi
fi
export PATH=/root/.cargo/bin:$PATH
cd "$src"
cargo build --release --locked -p candord -p candor-cli -p candor-gui -p candor-glasshouse 2>&1 | tail -3
bin="$src/target/release"
# Root itest binaries and the static workload, built here too so the distro
# matrix (vm/matrix.sh, WP31) runs them on the oldest glibc as well.
if [ "${CANDOR_ITEST:-0}" = 1 ]; then
mkdir -p "$out/itest"
cargo test --release --locked -p candor-itest --no-run --message-format=json 2>/dev/null |
    python3 -c 'import json,sys,shutil
for l in sys.stdin:
    m=json.loads(l)
    if m.get("reason")=="compiler-artifact" and m.get("executable") and m["target"]["kind"]==["test"]:
        shutil.copy(m["executable"], sys.argv[1]+"/candor-itest-"+m["target"]["name"])' "$out/itest"
gcc -static -O2 -Wall -Wextra -Werror -pthread -o "$out/itest/candor-wl" testkit/wl/wl.c
fi
echo "glibc needed: $(objdump -T "$bin"/candord "$bin"/candor "$bin"/candor-gui "$bin"/candor-glasshouse | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1)"
ldd "$bin/candord" | grep -q libbpf && { echo "libbpf is linked dynamically"; exit 1; } || echo "libbpf: static"

stage="$work/stage"; packaging/stage.sh "$bin" "$stage"

# --- .deb -------------------------------------------------------------------
deb="$work/deb"; cp -a "$stage" "$deb"; mkdir -p "$deb/DEBIAN"
install -m 0755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm "$deb/DEBIAN/"
(cd "$deb" && find etc -type f | sed 's|^|/|') > "$deb/DEBIAN/conffiles"
cat > "$deb/usr/share/doc/candor/copyright" <<COPY
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: candor
Source: https://github.com/lu7h9a/candor

Files: *
Copyright: 2026 Candor authors
License: MIT

License: MIT
$(sed 's/^$/./; s/^/ /' LICENSE)
COPY
printf 'candor (%s-1) unstable; urgency=medium\n\n  * Release %s.\n\n -- Candor <noreply@github.com>  %s\n' \
    "$ver" "$ver" "$(date -R)" | gzip -9n > "$deb/usr/share/doc/candor/changelog.Debian.gz"
size=$(du -sk --exclude=DEBIAN "$deb" | cut -f1)
cat > "$deb/DEBIAN/control" <<CTRL
Package: candor
Version: $ver-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Candor <noreply@github.com>
Installed-Size: $size
Depends: libc6 (>= 2.35), libelf1, zlib1g, libzstd1, systemd
Recommends: bubblewrap
Homepage: https://github.com/lu7h9a/candor
Description: process monitor that explains what programs do (eBPF)
 Candor shows what every program on the computer is doing (programs
 started, files opened, network connections), flags suspicious behaviour
 with plain-language explanations, and can run a program in a sandbox to
 show what it touches. The daemon watches the processes of all users.
CTRL
dpkg-deb --root-owner-group -Zxz --build "$deb" "$out/candor_${ver}-1_amd64.deb" >/dev/null

# --- .rpm -------------------------------------------------------------------
rpmbuild -bb --quiet --define "_topdir $work/rpm" --define "_stage $stage" \
    --define "_version $ver" packaging/rpm/candor.spec
cp "$work"/rpm/RPMS/x86_64/candor-"$ver"-1.x86_64.rpm "$out/"

# --- tarball + Arch PKGBUILD -------------------------------------------------
t="candor-${ver}-x86_64"; tdir="$work/$t"; mkdir -p "$tdir"
cp -a "$stage" "$tdir/root"
install -m 0755 packaging/tarball/install.sh packaging/tarball/uninstall.sh "$tdir/"
cp README.md LICENSE "$tdir/"
(cd "$tdir/root" && find . ! -type d | sed 's|^\.||' | sort) > "$tdir/MANIFEST"
tar -C "$work" --owner=0 --group=0 --numeric-owner -czf "$out/$t.tar.gz" "$t"
sha=$(sha256sum "$out/$t.tar.gz" | cut -d' ' -f1)
sed "s/@VERSION@/$ver/; s/@SHA256@/$sha/" packaging/arch/PKGBUILD > "$out/PKGBUILD"
cp packaging/arch/candor.install "$out/"

# --- lint ---------------------------------------------------------------------
lintian --no-tag-display-limit "$out/candor_${ver}-1_amd64.deb" > "$out/lintian.txt" 2>&1 || true
rpmlint "$out/candor-$ver-1.x86_64.rpm" > "$out/rpmlint.txt" 2>&1 || true
(cd "$out" && sha256sum ./*.deb ./*.rpm ./*.tar.gz > SHA256SUMS)
echo "lintian errors: $(grep -c '^E:' "$out/lintian.txt" || true), warnings: $(grep -c '^W:' "$out/lintian.txt" || true)"
echo "rpmlint: $(tail -1 "$out/rpmlint.txt")"
ls -l "$out"
