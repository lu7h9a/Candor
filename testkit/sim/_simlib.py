"""Shared guard for SysScope behaviour simulators (plan 5.7(2)).

Every simulator is harmless: it acts only inside the directory it is given,
and only if that directory contains the marker file `.sysscope-sim-ok`.
Network simulators talk only to 127.0.0.0/8 and a listener they start.
"""
import os
import sys

MARKER = ".sysscope-sim-ok"


def sim_dir():
    if len(sys.argv) < 2:
        sys.exit("usage: %s DIR   (DIR must contain %s)" % (os.path.basename(sys.argv[0]), MARKER))
    d = os.path.realpath(sys.argv[1])
    if not os.path.isfile(os.path.join(d, MARKER)):
        sys.exit("refusing: %s has no %s marker file" % (d, MARKER))
    return d
