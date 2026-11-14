#!/usr/bin/env bash
# stage.sh BIN_DIR DESTDIR - lays out SysScope's files under DESTDIR exactly
# as every package installs them (plan WP30, D21). Used by the .deb, .rpm,
# Arch and tarball builds, so all four install the same tree.
set -euo pipefail
bin=${1:?BIN_DIR}; dest=${2:?DESTDIR}
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
inst() { install -D -m "$1" "$2" "$dest$3"; }
# The Glasshouse helper sits next to sysscoped: the daemon runs only a
# root-owned helper from its own directory.
for b in sysscoped sysscope sysscope-gui sysscope-glasshouse; do
    inst 0755 "$bin/$b" "/usr/bin/$b"
    strip --strip-unneeded "$dest/usr/bin/$b"
done
inst 0644 "$repo/packaging/systemd/sysscoped.service" /usr/lib/systemd/system/sysscoped.service
inst 0644 "$repo/packaging/sysusers/sysscope.conf" /usr/lib/sysusers.d/sysscope.conf
for f in rules.toml allow.toml sysscoped.toml; do
    inst 0644 "$repo/packaging/etc/$f" "/etc/sysscope/$f"
done
inst 0644 "$repo/packaging/desktop/sysscope.desktop" /usr/share/applications/sysscope.desktop
inst 0644 "$repo/packaging/desktop/sysscope.svg" /usr/share/icons/hicolor/scalable/apps/sysscope.svg
doc=/usr/share/doc/sysscope
inst 0644 "$repo/README.md" "$doc/README.md"
inst 0644 "$repo/LICENSE" "$doc/LICENSE"
for f in THREAT_MODEL.md REAL_SAMPLES.md; do inst 0644 "$repo/docs/$f" "$doc/$f"; done
inst 0644 "$repo/packaging/postinstall-message.txt" "$doc/postinstall-message.txt"
for m in "$repo"/packaging/man/*.[18]; do
    sec=${m##*.}; base=$(basename "$m")
    install -d "$dest/usr/share/man/man$sec"
    gzip -9n -c "$m" > "$dest/usr/share/man/man$sec/$base.gz"
    chmod 0644 "$dest/usr/share/man/man$sec/$base.gz"
done
