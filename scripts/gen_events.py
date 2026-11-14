#!/usr/bin/env python3
"""Writes a synthetic events recording for core replay benchmarks (WP11).

usage: gen_events.py N OUT
Processes fork, exec, open files, connect and exit in a steady churn so the
retention limits are exercised; a full /proc scan and a tick every 10 000 events.
"""
import json, random, sys

n, out = int(sys.argv[1]), sys.argv[2]
rnd = random.Random(1)
ns = 1_000_000_000
with open(out, "w") as f:
    f.write(json.dumps({"candor_record": 1, "proto": 1, "daemon_version": "gen",
                        "kernel": "gen", "boot_to_wall_ns": 0, "features": [],
                        "act_enabled": False}) + "\n")
    live = [(100, 1)]
    next_pid = 1000
    ts = ns
    for i in range(1, n + 1):
        ts += 20_000  # 50 000 events per second
        tgid, start = rnd.choice(live)
        proc = {"tgid": tgid, "start": start}
        r = rnd.random()
        if r < 0.05 and len(live) < 3000:
            child = (next_pid, ts // 10_000_000)
            next_pid += 1
            live.append(child)
            kind = {"k": "Fork", "child": {"tgid": child[0], "start": child[1]}}
        elif r < 0.08 and len(live) > 1 and (tgid, start) != (100, 1):
            live.remove((tgid, start))
            kind = {"k": "Exit"}
        elif r < 0.10:
            kind = {"k": "Exec", "exe": "/usr/bin/prog%d" % rnd.randrange(50), "argv": "prog\\x00-x",
                    "argv_trunc": False, "fileless": False, "dev": 2050, "ino": rnd.randrange(1 << 20)}
        elif r < 0.95:
            ino = rnd.randrange(20000)
            kind = {"k": "Open", "path": "/home/u/dir%d/file%d" % (ino % 97, ino), "dev": 2050,
                    "ino": ino, "read": True, "write": r > 0.9, "create": False, "trunc": False,
                    "path_trunc": False}
        else:
            kind = {"k": "Connect", "family": "inet", "addr": "10.0.%d.%d" % (rnd.randrange(8), rnd.randrange(256)),
                    "port": 443, "sock": "stream"}
        f.write(json.dumps({"t": "RawEvent", "event": {"id": i, "ts_ns": ts, "proc": proc,
                            "tid": tgid, "uid": 1000, "kind": kind}}) + "\n")
        if i % 10_000 == 0:
            samples = [{"key": {"tgid": t, "start": s}, "ppid": 100, "exe": "/usr/bin/p", "comm": "p",
                        "uid": 1000, "kthread": False, "cpu_ticks": i // 1000, "rss": 1 << 20,
                        "threads": 1, "io_r": 0, "io_w": 0} for (t, s) in live]
            f.write(json.dumps({"t": "Samples", "ts_ns": ts, "samples": samples}) + "\n")
            f.write(json.dumps({"t": "Tick", "ts_ns": ts}) + "\n")
