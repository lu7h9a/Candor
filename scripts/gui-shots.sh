#!/usr/bin/env bash
# gui-shots.sh - renders the GUI headless (Xvfb + software GL) from the demo
# recording in 6 states, plus the Glasshouse report page from a real VM run,
# and checks every PNG is non-blank (>= 500 colours).
# Output: target/shots/*.png (plan WP20, `make gui-shot`).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
GUI=target/debug/candor-gui
CLI=target/debug/candor
OUT=target/shots
mkdir -p "$OUT"
FRAMES=fixtures/gui/demo.frames.jsonl
"$CLI" replay fixtures/gui/demo.events.jsonl --frames "$FRAMES" >/dev/null
# A following variant: the last snapshots report follow mode on bash 1030.
python3 - "$FRAMES" "$OUT/follow.frames.jsonl" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
lines = [json.loads(l) for l in open(src)]
tree = {1030, 1600}
with open(dst, "w") as f:
    for m in lines:
        if m.get("t") == "Snapshot":
            m["mode"] = {"follow": {"tgid": 1030, "start": 100}}
            for r in m["procs"]:
                r["followed"] = r["key"]["tgid"] in tree
        f.write(json.dumps(m) + "\n")
PY
export LIBGL_ALWAYS_SOFTWARE=1
shot() { # name, args...
    local name=$1; shift
    timeout 90 xvfb-run -a -s "-screen 0 1400x900x24" "$GUI" "$@" \
        --screenshot "$OUT/$name.png" --after-frames 60 2>/dev/null
    echo "shot: $OUT/$name.png"
}
shot system-wide --replay "$FRAMES" --pace max
shot detail-files --replay "$FRAMES" --pace max --select 1100 --tab files
shot detail-findings --replay "$FRAMES" --pace max --select 1600 --tab findings
shot following --replay "$OUT/follow.frames.jsonl" --pace max --select 1600
shot daemon-down --socket /run/candor-none/candor.sock
shot paused --replay "$FRAMES" --pace 200 --paused
python3 scripts/gen_gh_fixture.py >/dev/null
shot glasshouse-report --replay fixtures/gui/glasshouse.frames.jsonl --pace max --page glasshouse
python3 scripts/png_colours.py 500 "$OUT"/system-wide.png "$OUT"/detail-files.png \
    "$OUT"/detail-findings.png "$OUT"/following.png "$OUT"/daemon-down.png "$OUT"/paused.png \
    "$OUT"/glasshouse-report.png
