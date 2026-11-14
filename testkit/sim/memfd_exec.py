#!/usr/bin/env python3
"""R003 simulator: runs a copy of /bin/true from a memfd (no file on disk).
usage: memfd_exec.py DIR"""
import os
from _simlib import sim_dir

sim_dir()
fd = os.memfd_create("candor-sim", 0)
with open("/bin/true", "rb") as src:
    os.write(fd, src.read())
pid = os.fork()
if pid == 0:
    os.execve(fd, ["candor-sim"], {})
_, status = os.waitpid(pid, 0)
print("memfd_exec: child exited with", os.waitstatus_to_exitcode(status))
