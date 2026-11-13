#!/usr/bin/env python3
"""R011 simulator: a process asks to ptrace-attach to its sibling.
Starts two children; the second calls ptrace(PTRACE_ATTACH) on the first
(which it did not start), detaches if it was allowed, and both exit. With
Yama ptrace_scope >= 1 the kernel refuses the attach; the attempt is still
what R011 reports.
usage: ptrace_attach.py DIR"""
import ctypes
import os
import signal
import time
from _simlib import sim_dir

sim_dir()
PTRACE_ATTACH, PTRACE_DETACH = 16, 17
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
sleeper = os.fork()
if sleeper == 0:
    time.sleep(30)
    os._exit(0)
attacher = os.fork()
if attacher == 0:
    r = libc.ptrace(PTRACE_ATTACH, sleeper, None, None)
    if r == 0:
        os.waitpid(sleeper, 0)
        libc.ptrace(PTRACE_DETACH, sleeper, None, None)
        print("ptrace_attach: attached to sibling %d (detached)" % sleeper, flush=True)
    else:
        print("ptrace_attach: attach to sibling %d refused (errno %d)" % (sleeper, ctypes.get_errno()), flush=True)
    os._exit(0)
os.waitpid(attacher, 0)
os.kill(sleeper, signal.SIGKILL)
os.waitpid(sleeper, 0)
