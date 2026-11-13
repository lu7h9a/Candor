#!/usr/bin/env bash
# embed.sh SRC:DEST... - prints shell commands that recreate each host file
# SRC at DEST inside a guest (base64, mode kept). Used to hand test inputs
# such as testkit/sim/fake_malware.py to a VM test:
#   vm/run.sh debian12 "$(vm/embed.sh testkit/sim/x.py:/tmp/x.py)$(cat vm/tests/t.sh)"
set -eu
for spec in "$@"; do
    src="${spec%%:*}"; dst="${spec#*:}"
    mode=$(stat -c %a "$src")
    printf "base64 -d > %q <<'B64EOF'\n" "$dst"
    base64 -w 76 "$src"
    printf "B64EOF\nchmod %s %q\n" "$mode" "$dst"
done
# $(...) strips trailing newlines; a final comment line absorbs whatever is
# appended to it (e.g. the next script's "#!" line).
printf '# end of embedded files'
