#!/usr/bin/env bash
# readme-test.sh [distro] - plan WP33 Verify: every ```bash block of
# README.md, in order, run as an ordinary user in a fresh guest (default
# debian12) with the .deb from target/packages in its working directory.
# Blocks in ```text are other systems or reference lists (covered by the
# package tests on their distros, docs/PACKAGING.md).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
source "$here/lib.sh"
d=${1:-debian12}
deb=$(ls "$repo"/target/packages/candor_*_amd64.deb | head -1)
script=$(awk '/^```bash$/{on=1; next} /^```/{on=0} on' "$repo/README.md")
[ -n "$script" ] || die "no bash blocks in README.md"
"$here/down.sh" "$d" >/dev/null 2>&1 || true
"$here/up.sh" "$d" >&2
vm_ssh "$d" 'rm -rf ~/readme && mkdir ~/readme'
vm_ssh "$d" "cat > ~/readme/$(basename "$deb")" < "$deb"
vm_ssh "$d" 'cat > ~/readme/readme.sh' <<< "$script"
echo "== README commands ($(echo "$script" | grep -c .) lines) on $d"
set +e
vm_ssh "$d" 'cd ~/readme && sudo apt-get update -qq >/dev/null && bash -euxo pipefail readme.sh'
rc=$?
set -e
"$here/down.sh" "$d" >/dev/null
echo "README commands rc=$rc"
exit $rc
