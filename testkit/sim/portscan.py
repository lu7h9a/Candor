#!/usr/bin/env python3
"""R007 simulator: tries TCP connects to 127.0.0.1 ports FIRST..LAST (loopback
only; closed ports simply refuse). usage: portscan.py DIR [FIRST=20000] [LAST=20200]"""
import socket, sys
from _simlib import sim_dir

sim_dir()
first = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
last = int(sys.argv[3]) if len(sys.argv) > 3 else 20200
refused = 0
for port in range(first, last + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect(("127.0.0.1", port))
    except OSError:
        refused += 1
    finally:
        s.close()
print("portscan: %d ports tried on 127.0.0.1, %d refused" % (last - first + 1, refused))
