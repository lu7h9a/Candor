#!/usr/bin/env python3
"""Builds fixtures/gui/glasshouse.frames.jsonl, a GUI replay that ends with a
real Glasshouse report: the Welcome and first Snapshot of the demo replay
(with the "glasshouse" feature), then the GhStatus/GhReport messages the
daemon sent for fixtures/gui/glasshouse.report.json (captured from the WP24
debian12 VM run of testkit/sim/fake_malware.py).
usage: scripts/gen_gh_fixture.py"""
import json

demo = [json.loads(l) for l in open("fixtures/gui/demo.frames.jsonl")]
welcome = next(m for m in demo if m["t"] == "Welcome")
snap = next(m for m in demo if m["t"] == "Snapshot")
welcome["features"] = ["exec", "files", "network", "listen", "syscalls", "glasshouse"]
report = json.load(open("fixtures/gui/glasshouse.report.json"))
rid = report["run_id"]
live = [dict(d, states=["untouched"], size_after=None, entropy_after=None) for d in report["decoys"]]
out = [
    welcome,
    snap,
    {"t": "GhStatus", "state": "running", "run_id": rid, "message": "sample started", "decoys": live},
    {"t": "GhReport", "report": report},
    {"t": "GhStatus", "state": "finished", "run_id": rid,
     "message": "report saved to /var/lib/candor/reports/%s.json" % rid, "decoys": []},
]
with open("fixtures/gui/glasshouse.frames.jsonl", "w") as f:
    for m in out:
        f.write(json.dumps(m, separators=(",", ":")) + "\n")
print("wrote fixtures/gui/glasshouse.frames.jsonl (%d messages)" % len(out))
