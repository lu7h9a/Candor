#!/usr/bin/env bash
# gui-restart.sh - WP21: the GUI keeps running while the daemon goes away and
# comes back. A fake daemon (scripts/fake_daemon.py, Unix socket only) is
# stopped and restarted; screenshots at 3 s (connected), 8 s (down) and
# 15 s (recovered) go to target/shots/restart-*.png.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
SOCK=target/shots/fake.sock
mkdir -p target/shots
python3 scripts/fake_daemon.py "$SOCK" fixtures/gui/demo.frames.jsonl & fake=$!
sleep 1
LIBGL_ALWAYS_SOFTWARE=1 xvfb-run -a -s "-screen 0 1400x900x24" target/debug/sysscope-gui --socket "$SOCK" \
    --shot-at 3:target/shots/restart-1-connected.png --shot-at 8:target/shots/restart-2-down.png \
    --shot-at 15:target/shots/restart-3-recovered.png 2>/dev/null & gui=$!
sleep 5; kill "$fake"; wait "$fake" 2>/dev/null || true; rm -f "$SOCK"
sleep 5
python3 scripts/fake_daemon.py "$SOCK" fixtures/gui/demo.frames.jsonl & fake=$!
wait "$gui"
kill "$fake" 2>/dev/null || true
ls -1 target/shots/restart-*.png
