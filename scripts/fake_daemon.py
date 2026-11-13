#!/usr/bin/env python3
"""fake_daemon.py SOCKET FRAMES - a stand-in daemon for GUI tests: accepts
clients on a Unix socket (only), reads Hello/Subscribe, sends the Welcome and
then one Snapshot from FRAMES every 0.5 s, looping. No network, no root."""
import json, os, socket, struct, sys, threading, time

sock_path, frames = sys.argv[1], sys.argv[2]
msgs = [l.encode() for l in open(frames) if l.strip()]
welcome = next(m for m in msgs if b'"t":"Welcome"' in m)
snaps = [m for m in msgs if b'"t":"Snapshot"' in m]

def frame(b):
    return struct.pack("<I", len(b)) + b

def client(c):
    try:
        for _ in range(2):  # Hello, Subscribe
            n = struct.unpack("<I", c.recv(4, socket.MSG_WAITALL))[0]
            c.recv(n, socket.MSG_WAITALL)
        c.sendall(frame(welcome))
        i = 0
        while True:
            c.sendall(frame(snaps[i % len(snaps)]))
            i += 1
            time.sleep(0.5)
    except OSError:
        pass

if os.path.exists(sock_path):
    os.unlink(sock_path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(4)
while True:
    c, _ = s.accept()
    threading.Thread(target=client, args=(c,), daemon=True).start()
