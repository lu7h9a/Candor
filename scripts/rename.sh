#!/usr/bin/env bash
# rename.sh NEWNAME [DisplayName] [DIR] - renames the product everywhere in
# the tree at DIR (default: this repository): crates, binaries, the systemd
# unit, groups, paths (/etc, /run, /var/lib), the socket and the docs (plan
# WP33). The current name is read from crates/<name>-core. "<name>" ->
# NEWNAME, "<Name>" -> DisplayName (default: NEWNAME capitalised),
# "<NAME>" -> upper case. (Renamed from SysScope to Candor on 2026-11-15.)
# Text files only (binary files such as images are left alone); .git, target
# and fuzz/{target,artifacts} are skipped. Run it on a clean checkout and
# review the diff; CI runs it on a copy and builds the result.
set -euo pipefail
new=${1:?usage: rename.sh NEWNAME [DisplayName] [DIR]}
case "$new" in
    *[!a-z0-9]* | [!a-z]* ) echo "NEWNAME must be lower-case letters and digits, starting with a letter"; exit 2 ;;
esac
[ ${#new} -ge 3 ] && [ ${#new} -le 30 ] || { echo "NEWNAME must be 3-30 characters"; exit 2; }
cap="$(printf '%s' "${new:0:1}" | tr a-z A-Z)${new:1}"
display=${2:-$cap}
upper=$(printf '%s' "$new" | tr a-z A-Z)
dir=${3:-$(cd "$(dirname "$0")/.." && pwd)}
cd "$dir"
core=$(ls -d crates/*-core 2>/dev/null | head -1)
[ -n "$core" ] || { echo "no crates/<name>-core in $dir"; exit 2; }
old=$(basename "$core" -core)
oldcap="$(printf '%s' "${old:0:1}" | tr a-z A-Z)${old:1}"
oldupper=$(printf '%s' "$old" | tr a-z A-Z)
[ "$old" != "$new" ] || { echo "already named $new"; exit 2; }
# fuzz/corpus holds opaque fuzzer inputs: they are left as they are.
prune=(-path ./.git -o -path ./target -o -path ./fuzz/target -o -path ./fuzz/artifacts -o -path ./fuzz/corpus)
subst=(-e "s/$oldcap/$display/g" -e "s/$oldupper/$upper/g" -e "s/$old/$new/g")
# 1. Contents of text files, and of gzip-compressed text (recorded fixtures).
find . \( "${prune[@]}" \) -prune -o -type f -print0 |
    while IFS= read -r -d '' f; do
        case "$f" in
        *.gz)
            # Read the whole stream: `zgrep -q` stops at the first match, and on
            # some gzip versions the resulting SIGPIPE makes it report "no match".
            [ "$(zcat "$f" | grep -ci "$old" || true)" -gt 0 ] || continue
            zcat "$f" | sed "${subst[@]}" | gzip -9n > "$f.tmp" && mv "$f.tmp" "$f"
            continue ;;
        esac
        grep -Iq . "$f" 2>/dev/null || continue # binary or empty
        grep -qi "$old" "$f" || continue
        sed -i "${subst[@]}" "$f"
    done
# 2. File and directory names, deepest first.
find . \( "${prune[@]}" \) -prune -o -depth -name "*$old*" -print |
    while IFS= read -r p; do
        d=$(dirname "$p"); b=$(basename "$p")
        mv "$p" "$d/${b//$old/$new}"
    done
left=$(grep -rIil "$old" --exclude-dir=.git --exclude-dir=target --exclude-dir=corpus . || true)
for f in $(find . \( "${prune[@]}" \) -prune -o -type f -name '*.gz' -print); do
    [ "$(zcat "$f" | grep -ci "$old" || true)" -gt 0 ] && left="$left${left:+
}$f"
done
if [ -n "$left" ]; then echo "still mention $old:"; echo "$left"; exit 1; fi
echo "renamed to $new ($display) in $dir"
