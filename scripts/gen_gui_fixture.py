#!/usr/bin/env python3
"""Writes fixtures/gui/demo.events.jsonl: a deterministic, synthetic 75-second
desktop session used for GUI screenshots and GUI tests (WP20/WP21).

A normal desktop (systemd, kernel threads, sshd, two users' shells, a
browser, an editor, a cargo build) plus one suspicious program in /tmp that
reads an SSH key and connects to the same public address every 5 seconds.
Loss counters are non-zero so the loss indicator shows. No real data.
"""
import json, os, random

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "gui", "demo.events.jsonl")
SEC = 1_000_000_000
T0 = 1000 * SEC
rnd = random.Random(7)

procs = []  # (pid, ppid, exe, comm, uid, kthread, base_cpu, rss_mb, threads)
def p(pid, ppid, exe, comm, uid=0, kth=False, cpu=0.1, rss=8, thr=1):
    procs.append(dict(pid=pid, ppid=ppid, exe=exe, comm=comm, uid=uid, kth=kth, cpu=cpu, rss=rss, thr=thr))

p(1, 0, "/usr/lib/systemd/systemd", "systemd", cpu=0.2, rss=14)
p(2, 0, "", "kthreadd", kth=True, cpu=0.0, rss=0)
for i, n in enumerate(["kworker/0:1", "kworker/1:2", "ksoftirqd/0", "rcu_preempt", "kswapd0"]):
    p(10 + i, 2, "", n, kth=True, cpu=0.3 if i == 0 else 0.0, rss=0)
p(300, 1, "/usr/lib/systemd/systemd-journald", "systemd-journal", cpu=0.4, rss=30)
p(320, 1, "/usr/sbin/sshd", "sshd", cpu=0.0, rss=9)
p(340, 1, "/usr/sbin/cron", "cron", rss=3)
p(360, 1, "/usr/bin/dbus-daemon", "dbus-daemon", uid=101, rss=5)
p(900, 1, "/usr/lib/xorg/Xorg", "Xorg", cpu=3.5, rss=120, thr=4)
p(1000, 1, "/usr/bin/xfce4-session", "xfce4-session", uid=1000, cpu=0.5, rss=40, thr=3)
p(1010, 1000, "/usr/bin/xfce4-terminal", "xfce4-terminal", uid=1000, cpu=1.2, rss=60, thr=5)
p(1020, 1010, "/usr/bin/bash", "bash", uid=1000, rss=6)
p(1030, 1010, "/usr/bin/bash", "bash", uid=1000, rss=6)
p(1100, 1000, "/opt/firefox/firefox", "firefox", uid=1000, cpu=12.0, rss=780, thr=82)
for i in range(6):
    p(1110 + i, 1100, "/opt/firefox/firefox", "Isolated Web Co", uid=1000, cpu=2.0 + i, rss=180 + 20 * i, thr=28)
p(1200, 1000, "/usr/share/code/code", "code", uid=1000, cpu=4.0, rss=420, thr=40)
p(1300, 1020, "/home/u/.cargo/bin/cargo", "cargo", uid=1000, cpu=8.0, rss=150, thr=12)
for i in range(4):
    p(1310 + i, 1300, "/home/u/.rustup/toolchains/stable/bin/rustc", "rustc", uid=1000, cpu=95.0, rss=350, thr=6)
p(1400, 1030, "/usr/bin/python3.14", "python3", uid=1000, cpu=0.8, rss=35)
p(1500, 1, "/usr/sbin/sshd", "sshd", rss=8)
p(1510, 1500, "/usr/bin/bash", "bash", uid=1001, rss=6)
p(1520, 1510, "/usr/bin/top", "top", uid=1001, cpu=0.6, rss=4)
p(1600, 1030, "/tmp/.cache-x/update-helper", "update-helper", uid=1000, cpu=0.2, rss=12, thr=2)

def key(pid, start=100):
    return {"tgid": pid, "start": start}

lines = [{"sysscope_record": 1, "proto": 1, "daemon_version": "0.0.1", "kernel": "6.19.14+kali-amd64 (fixture)",
          "boot_to_wall_ns": 1_763_000_000 * SEC - T0, "features": ["exec", "files", "network", "listen", "syscalls"],
          "act_enabled": False}]
eid = [0]
def ev(ts, pid, kind, uid=1000):
    eid[0] += 1
    lines.append({"t": "RawEvent", "event": {"id": eid[0], "ts_ns": ts, "proc": key(pid), "tid": pid, "uid": uid, "kind": kind}})

def sample(ts, sec):
    out = []
    for q in procs:
        if q["pid"] == 1600 and sec < 5:
            continue
        cpu_ticks = int(q["cpu"] * sec)  # cpu% of one core = ticks per second at 100 Hz
        jitter = 1.0 + 0.1 * rnd.random()  # memory only; CPU must stay monotonic
        out.append({"key": key(q["pid"]), "ppid": q["ppid"], "exe": q["exe"], "comm": q["comm"], "uid": q["uid"],
                    "kthread": q["kth"], "cpu_ticks": cpu_ticks, "rss": int(q["rss"] * jitter * 1048576),
                    "threads": q["thr"], "io_r": sec * 4096, "io_w": sec * 1024})
    lines.append({"t": "Samples", "ts_ns": ts, "samples": out})

for sec in range(0, 76):
    ts = T0 + sec * SEC
    sample(ts, sec)
    # Busy background: firefox and code open their profile files.
    for _ in range(3):
        f = rnd.randrange(30)
        ev(ts + 1000, 1100, {"k": "Open", "path": "/home/u/.mozilla/firefox/abc.default/cache2/entries/%04X" % f,
                             "dev": 2050, "ino": 50000 + f, "read": True, "write": f % 3 == 0, "create": False,
                             "trunc": False, "path_trunc": False})
    ev(ts + 2000, 1200, {"k": "Open", "path": "/home/u/src/sysscope/crates/sysscope-gui/src/ui.rs", "dev": 2050,
                         "ino": 70001, "read": True, "write": sec % 10 == 0, "create": False, "trunc": False, "path_trunc": False})
    if rnd.random() < 0.3:  # irregular browsing traffic
        ev(ts + 3000, 1100, {"k": "Connect", "family": "inet6", "addr": "2001:db8::443", "port": 443, "sock": "stream"})
    if sec == 5:
        # The suspicious program starts from /tmp, reads a private key, ...
        ev(ts + 10, 1030, {"k": "Fork", "child": key(1600)})
        ev(ts + 20, 1600, {"k": "Exec", "exe": "/tmp/.cache-x/update-helper", "argv": "update-helper\\x00--quiet",
                           "argv_trunc": False, "fileless": False, "dev": 44, "ino": 777})
        lines.append({"t": "ExeMeta", "proc": key(1600), "trusted": False, "system_dir": False,
                      "home": "/home/u", "world_writable_dir": False})
        ev(ts + 30, 1600, {"k": "Open", "path": "/home/u/.ssh/id_ed25519", "dev": 2050, "ino": 60001, "read": True,
                           "write": False, "create": False, "trunc": False, "path_trunc": False})
        ev(ts + 40, 1600, {"k": "Open", "path": "/home/u/.bashrc", "dev": 2050, "ino": 60002, "read": True,
                           "write": True, "create": False, "trunc": False, "path_trunc": False})
    if sec >= 6 and (sec - 6) % 5 == 0:
        # ... and connects to the same public address every 5 seconds.
        ev(ts + 50, 1600, {"k": "Connect", "family": "inet", "addr": "93.184.216.34", "port": 443, "sock": "stream"})
    if sec % 2 == 0:
        ev(ts + 60, 1310 + (sec // 2) % 4, {"k": "Open", "path": "/home/u/src/sysscope/target/debug/deps/libx-%d.rlib" % sec,
                                           "dev": 2050, "ino": 80000 + sec, "read": False, "write": True, "create": True,
                                           "trunc": True, "path_trunc": False})
    if sec >= 30:
        lines.append({"t": "Loss", "loss": {"ringbuf": 12, "budget": 340, "scratch": 0, "since_ts_ns": T0}})
    lines.append({"t": "Tick", "ts_ns": ts + 500_000_000})

with open(OUT, "w") as f:
    for l in lines:
        f.write(json.dumps(l) + "\n")
print("wrote", os.path.normpath(OUT), len(lines), "lines")
