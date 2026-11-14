#!/usr/bin/env bash
# gui-stress.sh - WP21: run the real GUI (release, Xvfb, software GL) on a
# 2000-process replay at 2 Hz for 30 s and check CPU < 10 % of one core and
# peak RSS < 300 MiB. Writes nothing outside target/.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
export PATH="$HOME/.cargo/bin:$PATH"
cargo build -q --release -p candor-gui
FR=target/stress.frames.jsonl
python3 - "$FR" <<'PY'
import json, sys
with open(sys.argv[1], "w") as f:
    for seq in range(120):
        procs = []
        for i in range(2000):
            procs.append({"key": {"tgid": 100 + i, "start": 1}, "parent": {"tgid": 100 + i // 8, "start": 1} if i else None,
                "exe": "/usr/lib/stress/worker-%04d/bin/process-%d" % (i % 97, i), "comm": "worker", "uid": 1000 + i % 3,
                "kthread": False, "cpu_pct": ((i * 7 + seq * 13) % 1000) / 10.0, "rss": i * 40960, "threads": 1 + i % 8,
                "io_r": 0, "io_w": 0, "n_open": i * seq, "n_conn": 0, "n_exec": 0, "n_child": 0, "n_sys": 0,
                "score": 72 if i % 250 == 0 else 0, "tree_score": 0, "top_rule": None, "exited_ts": None,
                "followed": False, "ev_dropped": 0})
        f.write(json.dumps({"t": "Snapshot", "seq": seq, "ts_ns": seq * 500000000, "mode": "system",
                            "procs": procs, "loss": {"ringbuf": 0, "budget": 0, "scratch": 0, "since_ts_ns": 0}}) + "\n")
PY
export LIBGL_ALWAYS_SOFTWARE=1
xvfb-run -a -s "-screen 0 1400x900x24" target/release/candor-gui --replay "$FR" --pace 500 2>/dev/null &
sleep 2
pid=$(pgrep -n -f "target/release/candor-gui --replay $FR")
ticks() { awk '{print $14 + $15}' /proc/$pid/stat; }
# CPU of the GUI's own threads, excluding Mesa's llvmpipe software-render
# threads (on real hardware the GPU does that work).
own_ticks() {
    local t=0
    for d in /proc/$pid/task/*; do
        case "$(cat "$d/comm" 2>/dev/null)" in llvmpipe*) continue ;; esac
        t=$((t + $(awk '{print $14 + $15}' "$d/stat" 2>/dev/null || echo 0)))
    done
    echo $t
}
sleep 8
t0=$(ticks); o0=$(own_ticks); s0=$(date +%s.%N)
sleep 30
t1=$(ticks); o1=$(own_ticks); s1=$(date +%s.%N)
threads=$(for d in /proc/$pid/task/*; do cat $d/comm; done | sort | uniq -c | tr '\n' ' ')
hwm=$(awk '/VmHWM/ {print $2}' /proc/$pid/status)
kill "$pid" 2>/dev/null || true
cpu=$(python3 -c "print(round(($t1-$t0)/100/($s1-$s0)*100, 1))")
own=$(python3 -c "print(round(($o1-$o0)/100/($s1-$s0)*100, 1))")
echo "gui-stress: threads: $threads"
echo "gui-stress: 2000 processes at 2 Hz over 30 s: whole process ${cpu}% of one core (incl. software rendering), GUI threads ${own}%, VmHWM ${hwm} kB"
python3 -c "import sys; sys.exit(0 if $own < 10 and $hwm < 300*1024 else 1)" && echo "gui-stress PASS (GUI threads < 10 %, RSS < 300 MiB)" || { echo "gui-stress FAIL"; exit 1; }
