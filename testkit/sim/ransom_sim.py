#!/usr/bin/env python3
"""R005 simulator: generates N throw-away files inside DIR/files, then XORs
each one and renames it to .locked - all inside DIR, never anything else.
The XOR key is fixed and printed, so the files can be restored.
usage: ransom_sim.py DIR [N=25]"""
import os, sys
from _simlib import sim_dir

d = sim_dir()
n = int(sys.argv[2]) if len(sys.argv) > 2 else 25
work = os.path.join(d, "files")
os.makedirs(work, exist_ok=True)
for i in range(n):
    with open(os.path.join(work, "doc%03d.txt" % i), "w") as f:
        f.write("simulator document %d\n" % i * 20)
KEY = 0x5A
for i in range(n):
    p = os.path.join(work, "doc%03d.txt" % i)
    with open(p, "r+b") as f:
        data = bytes(b ^ KEY for b in f.read())
        f.seek(0)
        f.write(data)
    os.rename(p, p + ".locked")
print("ransom_sim: xor key 0x%02X, %d files renamed to .locked in %s" % (KEY, n, work))
