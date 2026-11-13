#!/usr/bin/env python3
"""Writes the replay fixtures for rules R001-R004 and R012 (plan 5.7(1), WP16).

Each case is fixtures/rules/<rule>/<case>/{events.jsonl, expected.json}.
expected.json holds the exact findings (rule, subject, tgid, confidence) and
the score of each listed process. The expected values are worked out by hand
from plan 5.2/5.4 and written here; they are NOT produced by running the code.
Score = round(100 * (1 - prod(1 - w*c))).
"""
import json, os, shutil, sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "rules")
SEC = 1_000_000_000
HEADER = {"sysscope_record": 1, "proto": 1, "daemon_version": "fixture", "kernel": "fixture",
          "boot_to_wall_ns": 0, "features": [], "act_enabled": False}


class Case:
    def __init__(self):
        self.lines = []
        self.id = 0
        self.ts = SEC

    def ev(self, tgid, kind, gap_ns=1_000_000):
        self.id += 1
        self.ts += gap_ns  # default 1 ms apart: decay is negligible for scores
        self.lines.append({"t": "RawEvent", "event": {
            "id": self.id, "ts_ns": self.ts, "proc": {"tgid": tgid, "start": 1},
            "tid": tgid, "uid": 1000, "kind": kind}})

    def exec_(self, tgid, exe, fileless=False):
        self.ev(tgid, {"k": "Exec", "exe": exe, "argv": exe, "argv_trunc": False,
                       "fileless": fileless, "dev": 1, "ino": 9})

    def meta(self, tgid, trusted=False, system_dir=False, home="/home/u", wwd=False):
        self.lines.append({"t": "ExeMeta", "proc": {"tgid": tgid, "start": 1}, "trusted": trusted,
                           "system_dir": system_dir, "home": home, "world_writable_dir": wwd})

    def proc(self, tgid, exe, **kw):
        self.exec_(tgid, exe)
        self.meta(tgid, **kw)

    def open_(self, tgid, path, read=True, write=False, create=False, trunc=False, dev=1, ino=1000):
        self.ev(tgid, {"k": "Open", "path": path, "dev": dev, "ino": ino, "read": read,
                       "write": write, "create": create, "trunc": trunc, "path_trunc": False})

    def rename(self, tgid, old, new, dev=1, ino=1000):
        self.ev(tgid, {"k": "Rename", "old": old, "new": new, "dev": dev, "ino": ino, "approx": False})

    def unlink(self, tgid, path, dev=1, ino=1000):
        self.ev(tgid, {"k": "Unlink", "path": path, "dev": dev, "ino": ino, "approx": False})

    def fork(self, tgid, child):
        self.ev(tgid, {"k": "Fork", "child": {"tgid": child, "start": 1}})

    def decoys(self, inodes):
        self.lines.append({"t": "Decoys", "inodes": inodes})

    def connect(self, tgid, addr, port, gap_ns=1_000_000, family="inet"):
        self.ev(tgid, {"k": "Connect", "family": family, "addr": addr, "port": port,
                       "sock": "stream"}, gap_ns)

    def budget(self, ts_s, drops):
        self.lines.append({"t": "BudgetDrops", "ts_ns": SEC + ts_s * SEC,
                           "drops": [[{"tgid": t, "start": 1}, n] for (t, n) in drops]})


def write(rule, name, case, findings, scores):
    d = os.path.join(ROOT, rule, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "events.jsonl"), "w") as f:
        f.write(json.dumps(HEADER) + "\n")
        for l in case.lines:
            f.write(json.dumps(l) + "\n")
    with open(os.path.join(d, "expected.json"), "w") as f:
        json.dump({"findings": [dict(zip(("rule", "subject", "tgid", "confidence"), x)) for x in findings],
                   "scores": {str(k): v for k, v in scores.items()}}, f, indent=2)
        f.write("\n")


P = 500
TOOL = "/home/u/bin/tool"  # not a temp dir, not a system dir, untrusted


def r001():
    c = Case(); c.proc(P, TOOL); c.open_(P, "/home/u/.ssh/id_ed25519")
    write("R001", "pos-ssh-key-untrusted", c, [("R001", "ssh_keys", P, 0.9)], {P: 54})
    c = Case(); c.proc(P, "/usr/bin/python3", trusted=True, system_dir=True); c.open_(P, "/etc/shadow")
    write("R001", "pos-shadow-system-exe", c, [("R001", "shadow", P, 0.5)], {P: 30})
    c = Case(); c.proc(P, TOOL); c.open_(P, "/home/u/.mozilla/firefox/abc.default/logins.json")
    write("R001", "pos-browser-logins", c, [("R001", "browser_creds", P, 0.9)], {P: 54})
    c = Case(); c.proc(P, TOOL); c.open_(P, "/home/u/.ssh/id_ed25519.pub")
    write("R001", "neg-public-key", c, [], {P: 0})
    c = Case(); c.proc(P, "/usr/bin/ssh", trusted=True, system_dir=True); c.open_(P, "/home/u/.ssh/id_rsa")
    write("R001", "neg-allowlisted-ssh", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); c.open_(P, "/home/u/.aws/credentials", read=False, write=True)
    write("R001", "neg-write-only", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); c.open_(P, "/home/u/.ssh/sub/id_x")
    write("R001", "boundary-deeper-dir", c, [], {P: 0})
    c = Case(); c.proc(P, "/usr/bin/ssh", trusted=False, system_dir=False); c.open_(P, "/home/u/.ssh/id_rsa")
    write("R001", "boundary-untrusted-allowlisted-path", c, [("R001", "ssh_keys", P, 0.9)], {P: 54})


def r002():
    c = Case(); c.proc(P, "/tmp/x")
    write("R002", "pos-tmp", c, [("R002", "/tmp/", P, 1.0)], {P: 40})
    c = Case(); c.proc(P, "/dev/shm/a")
    write("R002", "pos-dev-shm", c, [("R002", "/dev/shm/", P, 1.0)], {P: 40})
    c = Case(); c.proc(P, "/home/u/shared/x", wwd=True)
    write("R002", "pos-world-writable-dir", c, [("R002", "/home/u/shared/", P, 1.0)], {P: 40})
    c = Case(); c.proc(P, "/usr/bin/ls", trusted=True, system_dir=True)
    write("R002", "neg-system-exe", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); c.open_(P, "/tmp/lib.so")
    write("R002", "neg-reads-from-tmp", c, [], {P: 0})
    c = Case(); c.proc(P, "/home/u/bin/x", wwd=False)
    write("R002", "neg-home-bin", c, [], {P: 0})
    c = Case(); c.proc(P, "/tmpfoo/x")
    write("R002", "boundary-tmp-prefix-without-slash", c, [], {P: 0})
    c = Case(); c.proc(P, "/run/user/1000/x")
    write("R002", "boundary-run-user", c, [("R002", "/run/user/", P, 1.0)], {P: 40})


def r003():
    m = "/memfd:x (deleted)"
    c = Case(); c.exec_(P, m, fileless=True)
    write("R003", "pos-memfd", c, [("R003", "fileless", P, 0.9)], {P: 63})
    c = Case(); c.exec_(P, m, fileless=True); c.exec_(P, m, fileless=True)
    write("R003", "pos-twice-one-finding", c, [("R003", "fileless", P, 0.9)], {P: 63})
    c = Case(); c.proc(P, TOOL); c.fork(P, 501); c.exec_(501, m, fileless=True)
    write("R003", "pos-child", c, [("R003", "fileless", 501, 0.9)], {P: 0, 501: 63})
    c = Case(); c.proc(P, "/usr/bin/true", trusted=True, system_dir=True)
    write("R003", "neg-normal-exec", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); c.open_(P, "/memfd:x (deleted)")
    write("R003", "neg-open-memfd", c, [], {P: 0})
    c = Case(); c.exec_(P, "/memfd:looks-fileless", fileless=False)
    write("R003", "neg-name-only", c, [], {P: 0})
    c = Case(); c.exec_(P, "/tmp/deleted-bin", fileless=True)
    # R002 0.4*1.0 and R003 0.7*0.9: 1 - 0.6*0.37 = 0.778 -> 78
    write("R003", "boundary-with-r002", c, [("R002", "/tmp/", P, 1.0), ("R003", "fileless", P, 0.9)], {P: 78})
    c = Case(); c.exec_(777, m, fileless=True)
    write("R003", "boundary-unknown-process", c, [("R003", "fileless", 777, 0.9)], {777: 63})


def r004():
    vim = dict(trusted=True, system_dir=True)
    c = Case(); c.proc(P, "/usr/bin/vim", **vim); c.open_(P, "/home/u/.bashrc", read=False, write=True)
    write("R004", "pos-bashrc", c, [("R004", "shell_rc", P, 0.8)], {P: 48})
    c = Case(); c.proc(P, TOOL); c.open_(P, "/etc/ld.so.preload", read=False, write=True, create=True)
    write("R004", "pos-ld-so-preload", c, [("R004", "ld_so_preload", P, 1.0)], {P: 60})
    c = Case(); c.proc(P, TOOL); c.rename(P, "/home/u/.ssh/tmpkeys", "/home/u/.ssh/authorized_keys")
    write("R004", "pos-rename-into-authorized-keys", c, [("R004", "ssh_authorized_keys", P, 1.0)], {P: 60})
    c = Case(); c.proc(P, "/usr/bin/vim", **vim); c.open_(P, "/home/u/.bashrc")
    write("R004", "neg-read-bashrc", c, [], {P: 0})
    c = Case(); c.proc(P, "/usr/bin/dpkg", **vim); c.open_(P, "/etc/systemd/system/x.service", read=False, write=True, create=True)
    write("R004", "neg-allowlisted-dpkg", c, [], {P: 0})
    c = Case(); c.proc(P, "/usr/bin/vim", **vim); c.open_(P, "/home/u/.bashrc.bak", read=False, write=True)
    write("R004", "neg-backup-copy", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); c.open_(P, "/etc/cron.d/job", read=False, write=True, create=True)
    write("R004", "boundary-cron-d", c, [("R004", "cron", P, 0.8)], {P: 48})
    c = Case(); c.proc(P, TOOL); c.rename(P, "/home/u/.bashrc", "/home/u/.bashrc.old")
    write("R004", "boundary-rename-out-of-class", c, [], {P: 0})


def r012():
    c = Case(); c.decoys([[1, 100]]); c.proc(P, TOOL); c.open_(P, "/home/u/Documents/a.docx", ino=100)
    write("R012", "pos-read", c, [("R012", "decoy", P, 0.8)], {P: 72})
    c = Case(); c.decoys([[1, 100]]); c.proc(P, TOOL); c.unlink(P, "/home/u/Documents/a.docx", ino=100)
    write("R012", "pos-unlink", c, [("R012", "decoy", P, 1.0)], {P: 90})
    c = Case(); c.decoys([[1, 100]]); c.proc(P, TOOL); c.rename(P, "/home/u/a.docx", "/home/u/a.docx.locked", ino=100)
    write("R012", "pos-rename", c, [("R012", "decoy", P, 1.0)], {P: 90})
    c = Case(); c.decoys([[1, 100]]); c.proc(P, TOOL); c.open_(P, "/home/u/other", ino=101)
    write("R012", "neg-other-inode", c, [], {P: 0})
    c = Case(); c.decoys([[1, 100]]); c.decoys([]); c.proc(P, TOOL); c.open_(P, "/home/u/a.docx", ino=100)
    write("R012", "neg-decoys-cleared", c, [], {P: 0})
    c = Case(); c.decoys([[1, 100]]); c.proc(P, TOOL); c.open_(P, "/mnt/a.docx", dev=2, ino=100)
    write("R012", "neg-same-inode-other-device", c, [], {P: 0})
    c = Case(); c.decoys([[1, 100]]); c.proc(P, TOOL); c.open_(P, "/home/u/a", ino=100); c.open_(P, "/home/u/a", read=False, write=True, ino=100)
    write("R012", "boundary-read-then-write", c, [("R012", "decoy", P, 1.0)], {P: 90})
    c = Case(); c.decoys([[1, 100]]); c.proc(P, TOOL); c.open_(P, "/home/u/.ssh/id_rsa", ino=100)
    # R012 0.9*0.8=0.72 and R001 0.6*0.9=0.54: 1 - 0.28*0.46 = 0.8712 -> 87
    write("R012", "boundary-also-credential", c, [("R001", "ssh_keys", P, 0.9), ("R012", "decoy", P, 0.8)], {P: 87})


def rewrite_rename(c, n, new_ext=lambda i: "locked", gap_ns=1_000_000, base="/home/u/docs"):
    for i in range(n):
        c.open_(P, "%s/f%d.txt" % (base, i), read=False, write=True, ino=10 + i)
        c.ev(P, {"k": "Rename", "old": "%s/f%d.txt" % (base, i),
                 "new": "%s/f%d.txt.%s" % (base, i, new_ext(i)), "dev": 1, "ino": 10 + i,
                 "approx": False}, gap_ns)


def r005():
    # w 0.8: c 0.9 -> 72, c 0.5 -> 40, c 0.4 -> 32
    c = Case(); c.proc(P, TOOL); rewrite_rename(c, 20)
    write("R005", "pos-rename-common-ext", c, [("R005", "mass_rewrite", P, 0.9)], {P: 72})
    c = Case(); c.proc(P, TOOL)
    for i in range(20):
        c.open_(P, "/home/u/docs/f%d.txt.enc" % i, read=False, write=True, create=True, ino=1000 + i)
        c.unlink(P, "/home/u/docs/f%d.txt" % i, ino=10 + i)
    write("R005", "pos-new-sibling-then-unlink", c, [("R005", "mass_rewrite", P, 0.9)], {P: 72})
    c = Case(); c.proc(P, TOOL); rewrite_rename(c, 20, new_ext=lambda i: "x%d" % i)
    write("R005", "pos-mixed-extensions", c, [("R005", "mass_rewrite", P, 0.5)], {P: 40})
    c = Case(); c.proc(P, TOOL)
    for i in range(30):
        c.open_(P, "/home/u/d%d/f%d" % (i % 3, i), read=False, write=True, trunc=True, ino=10 + i)
    write("R005", "pos-truncate-existing", c, [("R005", "mass_rewrite", P, 0.4)], {P: 32})
    c = Case(); c.proc(P, "/usr/bin/tar", trusted=True, system_dir=True)
    for i in range(100):
        c.open_(P, "/home/u/x/f%d" % i, read=False, write=True, create=True, trunc=True, ino=10 + i)
    write("R005", "neg-tar-extract", c, [], {P: 0})
    c = Case(); c.proc(P, "/usr/bin/git", trusted=True, system_dir=True); rewrite_rename(c, 30, base="/home/u/repo/.git/objects")
    write("R005", "neg-excluded-git-dir", c, [], {P: 0})
    c = Case(); c.proc(P, "/usr/bin/mv", trusted=True, system_dir=True)
    for i in range(30):
        c.rename(P, "/home/u/docs/f%d.txt" % i, "/home/u/docs/f%d.bak" % i, ino=10 + i)
    write("R005", "neg-renames-without-writes", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL)
    for i in range(30):
        c.open_(P, "/home/u/d%d/f%d" % (i % 2, i), read=False, write=True, trunc=True, ino=10 + i)
    write("R005", "neg-truncate-two-dirs", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); rewrite_rename(c, 19)
    write("R005", "boundary-19-files", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); rewrite_rename(c, 20)
    write("R005", "boundary-20-files", c, [("R005", "mass_rewrite", P, 0.9)], {P: 72})
    c = Case(); c.proc(P, TOOL); rewrite_rename(c, 20, gap_ns=600_000_000)  # spans 12 s > 10 s window
    write("R005", "boundary-outside-window", c, [], {P: 0})


def beacon(c, addr, port, gaps_s):
    c.connect(P, addr, port)
    for g in gaps_s:
        c.connect(P, addr, port, gap_ns=int(g * SEC))


def r006():
    # w 0.5: c 0.6 -> 30, public c 0.8 -> 40
    c = Case(); c.proc(P, TOOL); beacon(c, "10.1.2.3", 443, [10] * 7)
    write("R006", "pos-private-every-10s", c, [("R006", "10.1.2.3:443", P, 0.6)], {P: 30})
    c = Case(); c.proc(P, TOOL); beacon(c, "93.184.216.34", 443, [30] * 5)
    write("R006", "pos-public-every-30s", c, [("R006", "93.184.216.34:443", P, 0.8)], {P: 40})
    c = Case(); c.proc(P, TOOL); beacon(c, "10.1.2.3", 443, [9, 11] * 4)  # cv 0.10
    write("R006", "pos-small-jitter", c, [("R006", "10.1.2.3:443", P, 0.6)], {P: 30})
    c = Case(); c.proc(P, TOOL); beacon(c, "127.0.0.1", 8080, [10] * 7)
    write("R006", "neg-loopback", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); beacon(c, "10.1.2.3", 443, [2, 30, 5, 60, 1, 20, 7])
    write("R006", "neg-irregular", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL)
    for i in range(8):
        c.connect(P, "/run/x.sock", 0, gap_ns=10 * SEC, family="unix")
    write("R006", "neg-unix-socket", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); beacon(c, "10.1.2.3", 443, [15] * 4)  # 5 connects, span 60
    write("R006", "boundary-5-connects", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); beacon(c, "10.1.2.3", 443, [15] * 5)  # 6 connects, span 75
    write("R006", "boundary-6-connects", c, [("R006", "10.1.2.3:443", P, 0.6)], {P: 30})
    # 6 connects, gaps 17.2/22.8: mean 19.44, sd 2.743, cv 0.141 -> fires
    c = Case(); c.proc(P, TOOL); beacon(c, "10.1.2.3", 443, [17.2, 22.8, 17.2, 22.8, 17.2, 22.8])
    write("R006", "boundary-cv-0.14", c, [("R006", "10.1.2.3:443", P, 0.6)], {P: 30})
    # gaps 16.8/23.2: cv 0.162 at 6 connects and 0.160 at 7 -> never fires
    c = Case(); c.proc(P, TOOL); beacon(c, "10.1.2.3", 443, [16.8, 23.2, 16.8, 23.2, 16.8, 23.2])
    write("R006", "boundary-cv-0.16", c, [], {P: 0})


def r007():
    # w 0.5, c 0.7 -> 35
    c = Case(); c.proc(P, TOOL)
    for port in range(20000, 20030):
        c.connect(P, "127.0.0.1", port)
    write("R007", "pos-ports-one-addr", c, [("R007", "fanout", P, 0.7)], {P: 35})
    c = Case(); c.proc(P, TOOL)
    for i in range(1, 51):
        c.connect(P, "10.0.0.%d" % i, 80)
    write("R007", "pos-addrs-one-port", c, [("R007", "fanout", P, 0.7)], {P: 35})
    c = Case(); c.proc(P, TOOL)
    for a in range(1, 6):
        for port in range(1000, 1020):
            c.connect(P, "10.0.0.%d" % a, port)
    write("R007", "pos-100-destinations", c, [("R007", "fanout", P, 0.7)], {P: 35})
    c = Case(); c.proc(P, TOOL)
    for i in range(1, 50):
        c.connect(P, "10.0.0.%d" % i, 80)
    write("R007", "neg-49-addrs", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL)
    for i in range(30):
        c.connect(P, "10.0.0.1", 443)
    write("R007", "neg-same-destination", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL)
    for port in range(20000, 20030):
        c.connect(P, "127.0.0.1", port, gap_ns=SEC // 2)  # at most 21 in any 10 s
    write("R007", "neg-slow-scan", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL)
    for port in range(20000, 20024):
        c.connect(P, "127.0.0.1", port)
    write("R007", "boundary-24-ports", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL)
    for port in range(20000, 20025):
        c.connect(P, "127.0.0.1", port)
    write("R007", "boundary-25-ports", c, [("R007", "fanout", P, 0.7)], {P: 35})


def r008():
    # w 0.3, c 0.6 -> 18
    c = Case(); c.proc(P, TOOL)
    for t in (1, 2, 3):
        c.budget(t, [(P, 100)])
    write("R008", "pos-three-seconds", c, [("R008", "flood", P, 0.6)], {P: 18})
    c = Case(); c.proc(P, TOOL)
    for t in range(1, 6):
        c.budget(t, [(P, 100)])
    write("R008", "pos-five-seconds-one-finding", c, [("R008", "flood", P, 0.6)], {P: 18})
    c = Case(); c.proc(P, TOOL); c.proc(501, TOOL)
    for t in (1, 2, 3):
        c.budget(t, [(P, 5), (501, 7)])
    write("R008", "pos-two-processes", c, [("R008", "flood", P, 0.6), ("R008", "flood", 501, 0.6)], {P: 18, 501: 18})
    c = Case(); c.proc(P, TOOL)
    for t in (1, 2, 4):
        c.budget(t, [(P, 100)])
    write("R008", "neg-gap-in-seconds", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL)
    for t in (1, 2, 3):
        c.budget(t, [(P, 0)])
    write("R008", "neg-zero-drops", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL); c.proc(501, TOOL)
    for t in (1, 2, 3):
        c.budget(t, [(501 if t == 2 else P, 50)])
    write("R008", "neg-interrupted-by-other-process", c, [], {P: 0, 501: 0})
    c = Case(); c.proc(P, TOOL)
    for t in (1, 2):
        c.budget(t, [(P, 100)])
    write("R008", "boundary-two-seconds", c, [], {P: 0})
    c = Case(); c.proc(P, TOOL)
    for t in (1, 2):
        c.budget(t, [(P, 100)])
    c.budget(3, [(501, 1)])
    for t in (4, 5, 6):
        c.budget(t, [(P, 100)])
    write("R008", "boundary-restart-after-reset", c, [("R008", "flood", P, 0.6)], {P: 18})


if __name__ == "__main__":
    for r in ("R001", "R002", "R003", "R004", "R005", "R006", "R007", "R008", "R012"):
        shutil.rmtree(os.path.join(ROOT, r), ignore_errors=True)
    r001(); r002(); r003(); r004(); r012(); r005(); r006(); r007(); r008()
    print("wrote fixtures under", os.path.normpath(ROOT))
