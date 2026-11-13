#!/usr/bin/env bash
# curl 20 URLs from a local web server on 127.0.0.1.
source "$(dirname "$0")/_common.sh"
if [ "$step" = setup ]; then mkdir -p www && for i in $(seq 1 20); do echo "page $i" > "www/p$i.html"; done; exit 0; fi
python3 -u -m http.server 0 --bind 127.0.0.1 --directory www > srv.log 2>&1 &
srv=$!
for _ in $(seq 1 50); do port=$(grep -o 'port [0-9]*' srv.log | awk '{print $2}'); [ -n "$port" ] && break; sleep 0.1; done
for i in $(seq 1 20); do curl -s "http://127.0.0.1:$port/p$i.html" > /dev/null; done
kill $srv; wait $srv 2>/dev/null || true
