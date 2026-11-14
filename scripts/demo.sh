#!/usr/bin/env bash
# demo.sh - stages the 60-second demo (docs/DEMO.md, plan 8.3) so the
# recording needs only clicks. Needs the daemon running (systemctl start
# candord) and sudo for the throwaway demo home. Everything it creates is
# harmless (testkit/sim) and removed at the end.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
sim="$here/testkit/sim"
demo_home=/home/candor-demo
tmpdir=/tmp/candor-demo
pause() { read -r -p "$1 [Enter] " _; }
cleanup() { sudo rm -rf "$demo_home"; rm -rf "$tmpdir"; }
trap cleanup EXIT

systemctl is-active --quiet candord || { echo "start the daemon first: sudo systemctl start candord"; exit 1; }
# A throwaway home, so the fake key sits where real keys live (~/.ssh/id_*).
sudo mkdir -p "$demo_home" && sudo chown "$(id -u):$(id -g)" "$demo_home"
touch "$demo_home/.candor-sim-ok"
mkdir -p "$tmpdir" && touch "$tmpdir/.candor-sim-ok"

echo "1. Open candor-gui. Sort by 'conns', click a browser, show the Files,"
echo "   Network and Syscalls tabs, press 'Follow this process tree', then unfollow."
pause "When ready for the alerts,"
echo "2. A program reads a (fake) private SSH key, then one runs from /tmp:"
python3 "$sim/cred_read.py" "$demo_home"
python3 "$sim/tmp_exec.py" "$tmpdir"
echo "   Two alerts appear in the GUI (R001, R002): open one and show its evidence."
pause "When ready for Glasshouse,"
echo "3. Glasshouse page -> Browse -> $sim/fake_malware.py -> Run in Glasshouse."
echo "   The decoy tiles change live; then scroll the before/after report."
echo "   Keep the yellow warning text in frame."
pause "When done (cleans up),"
