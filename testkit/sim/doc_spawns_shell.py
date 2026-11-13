#!/usr/bin/env python3
"""R009 simulator: a program named like a document viewer starts a shell.
Copies /bin/sh into DIR under the name "evince" (a renamed copy, so nothing
on the system is touched) and has it run a shell command in a child.
usage: doc_spawns_shell.py DIR"""
import os
import shutil
import subprocess
from _simlib import sim_dir

d = sim_dir()
viewer = os.path.join(d, "evince")
shutil.copy2("/bin/sh", viewer)
os.chmod(viewer, 0o755)
# "; true" keeps the copy alive as the parent (no exec-in-place of the last command).
subprocess.run([viewer, "-c", "/bin/sh -c 'echo document says hi' ; true"], check=True)
os.unlink(viewer)
print("doc_spawns_shell: %s started /bin/sh" % viewer)
