#!/usr/bin/env python3
"""R006 simulator: starts a listener on 127.0.0.1 and connects to it N times
every INTERVAL seconds. Loopback only. (R006 ignores loopback on purpose, so
the end-to-end test uses this to check the rule stays quiet for local
traffic and adds a fixture for a non-loopback destination.)
usage: beacon.py DIR [N=8] [INTERVAL=5]"""
import socket, sys, time
from _simlib import sim_dir

sim_dir()
n = int(sys.argv[2]) if len(sys.argv) > 2 else 8
interval = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("127.0.0.1", 0))
srv.listen(16)
port = srv.getsockname()[1]
for i in range(n):
    c = socket.create_connection(("127.0.0.1", port))
    conn, _ = srv.accept()
    conn.close()
    c.close()
    if i + 1 < n:
        time.sleep(interval)
print("beacon: %d connects to 127.0.0.1:%d every %.1fs" % (n, port, interval))
