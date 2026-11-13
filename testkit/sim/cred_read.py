#!/usr/bin/env python3
"""R001 simulator: creates a FAKE private key inside DIR/.ssh and reads it.
usage: cred_read.py DIR"""
import os
from _simlib import sim_dir

d = sim_dir()
os.makedirs(os.path.join(d, ".ssh"), mode=0o700, exist_ok=True)
key = os.path.join(d, ".ssh", "id_ed25519")
with open(key, "w") as f:
    f.write("-----BEGIN FAKE SYSSCOPE SIMULATOR KEY-----\nnot a real key\n")
with open(key) as f:
    f.read()
print("cred_read: read", key)
