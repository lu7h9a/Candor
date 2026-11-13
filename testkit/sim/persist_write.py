#!/usr/bin/env python3
"""R004 simulator: appends a comment to DIR/.bashrc (never the real one).
The end-to-end test adds DIR/.bashrc to the persistence class.
usage: persist_write.py DIR"""
import os
from _simlib import sim_dir

d = sim_dir()
rc = os.path.join(d, ".bashrc")
with open(rc, "a") as f:
    f.write("# written by the SysScope persistence simulator\n")
print("persist_write: wrote", rc)
