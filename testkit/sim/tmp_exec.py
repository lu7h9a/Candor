#!/usr/bin/env python3
"""R002 simulator: copies /bin/true into DIR and runs it from there.
Pass a DIR under /tmp to trigger the rule. usage: tmp_exec.py DIR"""
import os, shutil, subprocess
from _simlib import sim_dir

d = sim_dir()
exe = os.path.join(d, "sim-tmp-exec")
shutil.copy("/bin/true", exe)
os.chmod(exe, 0o755)
subprocess.run([exe], check=True)
print("tmp_exec: ran", exe)
