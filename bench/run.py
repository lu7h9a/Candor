#!/usr/bin/env python3
"""bench/run.py - tracer overhead benchmarks (plan WP14), run by `make bench`.

Each benchmark runs ROUNDS times in every mode, modes alternating within a
round (off, on, ...), so drifting machine load hits all modes alike:
  off      no daemon
  on       sysscoped --dev (syscall counting on, the default)
  sysoff   sysscoped --dev --syscalls off            (getppid only)
  follow   sysscoped --dev following an unrelated idle process
Then the idle daemon's CPU share over 5 minutes and its RSS. Writes
docs/BENCH.md; exits 0 only if every threshold in bench/thresholds.toml holds.
The daemon runs as root through `sudo -n`; benchmarks run as the user.
"""
import json, os, re, shutil, signal, statistics, subprocess, sys, tempfile, time, tomllib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REL = os.path.join(REPO, "target", "release")
T = tomllib.load(open(os.path.join(REPO, "bench", "thresholds.toml"), "rb"))
ROUNDS = int(os.environ.get("BENCH_ROUNDS", "10"))
QUICK = os.environ.get("BENCH_QUICK") == "1"   # development only: smaller sizes
WORK = os.path.join(REPO, "target", "bench")


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, check=True, **kw)


class Daemon:
    def __init__(self, extra=()):
        self.log = open(os.path.join(WORK, "daemon.log"), "w")
        self.p = subprocess.Popen(["sudo", "-n", os.path.join(REL, "sysscoped"), "--dev", *extra],
                                  stdout=subprocess.DEVNULL, stderr=self.log)
        for _ in range(200):
            m = re.search(r"pid (\d+)", open(self.log.name).read())
            if m:
                self.pid = int(m.group(1))
                break
            time.sleep(0.1)
        else:
            raise SystemExit("daemon did not start: " + open(self.log.name).read())
        time.sleep(3)  # first snapshots, /proc scan

    def stop(self):
        subprocess.run(["sudo", "-n", "kill", "-INT", str(self.pid)])
        self.p.wait(timeout=60)


def timed(fn):
    t = time.perf_counter()
    fn()
    return time.perf_counter() - t


# --- benchmarks --------------------------------------------------------------
SRC = os.path.join(WORK, "src")


def freeze_source():
    """A copy of the repository's source, taken once: the cargo benchmark
    builds the same code in every round even if the tree is edited."""
    shutil.rmtree(SRC, ignore_errors=True)
    shutil.copytree(REPO, SRC, ignore=shutil.ignore_patterns("target", ".git"))


def cargo_build():
    tgt = os.path.join(WORK, "cargo-target")
    shutil.rmtree(tgt, ignore_errors=True)
    crates = "-p sysscope-proto -p sysscope-core" if QUICK else "--workspace"
    sh(f"cargo build -q --offline {crates} --target-dir {tgt}", cwd=SRC)


C_TGZ = os.path.join(WORK, "cproj.tgz")


def make_c_project():
    src = os.path.join(WORK, "cproj")
    shutil.rmtree(src, ignore_errors=True)
    os.makedirs(src)
    n = 40 if QUICK else 300
    for i in range(n):
        body = "\n".join(f"static int g{j}(int x) {{ return x * {j} + {i}; }}" for j in range(60))
        open(os.path.join(src, f"m{i}.c"), "w").write(
            body + f"\nint f{i}(int x) {{ int s = 0; for (int k = 0; k < x; k++) s += " +
            " + ".join(f"g{j}(k)" for j in range(0, 60, 6)) + "; return s; }\n")
    open(os.path.join(src, "main.c"), "w").write("int f0(int);\nint main(void) { return f0(3) > 0 ? 0 : 1; }\n")
    open(os.path.join(src, "Makefile"), "w").write(
        "CFLAGS := -O2\nOBJ := $(patsubst %.c,%.o,$(wildcard *.c))\nprog: $(OBJ)\n\t$(CC) -o $@ $^\n")
    sh(f"tar czf {C_TGZ} -C {WORK} cproj")
    shutil.rmtree(src)


def c_make():
    d = os.path.join(WORK, "cbuild")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    sh(f"tar xzf {C_TGZ} -C {d} && make -s -C {d}/cproj -j{os.cpu_count()}")


def wl(*args):
    d = os.path.join(WORK, "wl")
    shutil.rmtree(d, ignore_errors=True)
    subprocess.run([os.path.join(REL, "sysscope-wl"), "--dir", d, *args], check=True,
                   stdout=subprocess.DEVNULL)


BENCH = [
    ("macro_cargo_build", "clean `cargo build` of this repo", cargo_build, ["off", "on", "follow"]),
    ("macro_c_make", "unpack + `make -j` of a 300-file C project", c_make, ["off", "on", "follow"]),
    ("micro_open_close", "500 000 x open/close", lambda: wl("open-read", "50000" if QUICK else "500000"),
     ["off", "on", "follow"]),
    ("micro_getppid", "5 000 000 x getppid", lambda: wl("syscalls", "getppid", "500000" if QUICK else "5000000"),
     ["off", "on", "sysoff", "follow"]),
]


def start(mode):
    if mode == "off":
        return None
    if mode == "sysoff":
        return Daemon(["--syscalls", "off"])
    d = Daemon()
    if mode == "follow":
        d.sleeper = subprocess.Popen(["sleep", "100000"])
        out = subprocess.run([os.path.join(REL, "sysscope"), "follow", str(d.sleeper.pid)],
                             capture_output=True, text=True)
        if "following" not in out.stdout:
            raise SystemExit("follow failed: " + out.stdout + out.stderr)
    return d


def stop(d):
    if d is None:
        return
    if getattr(d, "sleeper", None):
        d.sleeper.kill()
        d.sleeper.wait()
    d.stop()


def measure(name, fn, modes):
    times = {m: [] for m in modes}
    for r in range(ROUNDS):
        for m in modes:
            d = start(m)
            try:
                times[m].append(timed(fn))
            finally:
                stop(d)
        print(f"  {name} round {r + 1}/{ROUNDS}: " +
              ", ".join(f"{m} {times[m][-1]:.3f}s" for m in modes), flush=True)
    return times


def stats(xs):
    med = statistics.median(xs)
    return med, (max(xs) - min(xs)) / med if med else 0.0


def idle():
    d = Daemon()
    tck = os.sysconf("SC_CLK_TCK")

    def cpu():
        f = open(f"/proc/{d.pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / tck

    def rss():
        for l in open(f"/proc/{d.pid}/status"):
            if l.startswith("VmRSS:"):
                return int(l.split()[1]) / 1024
        return 0.0

    secs = 60 if QUICK else 300
    c0, t0, peak = cpu(), time.time(), 0.0
    while time.time() - t0 < secs:
        time.sleep(10)
        peak = max(peak, rss())
    share = (cpu() - c0) / (time.time() - t0)
    d.stop()
    return share, peak, secs


def main():
    os.makedirs(WORK, exist_ok=True)
    subprocess.run(["sudo", "-n", "true"], check=True)
    make_c_project()
    freeze_source()
    gov = open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read().strip() \
        if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") else "unknown"
    rows, fails = [], []
    only = [x for x in os.environ.get("BENCH_ONLY", "").split(",") if x]
    for key, desc, fn, modes in BENCH:
        if only and key not in only:
            continue
        print(f"== {key}", flush=True)
        times = measure(key, fn, modes)
        st = {m: stats(v) for m, v in times.items()}
        if any(s[1] > T["max_spread"] for s in st.values()):
            print(f"  spread over {T['max_spread']:.0%}: rerunning", flush=True)
            times = measure(key, fn, modes)
            st = {m: stats(v) for m, v in times.items()}
        base = st["off"][0]
        for m in modes:
            if m == "off":
                continue
            over = st[m][0] / base - 1
            if m == "follow":
                lim = T["follow_mode_open_close"] if key == "micro_open_close" else T["follow_mode_any"]
            elif key == "micro_getppid":
                lim = T["micro_getppid_count"] if m == "on" else T["micro_getppid_syscalls_off"]
            else:
                lim = T[key]
            ok = over <= lim and st[m][1] <= T["max_spread"] and st["off"][1] <= T["max_spread"]
            rows.append((key, desc, m, base, st[m][0], over, lim, max(st[m][1], st["off"][1]), ok))
            if not ok:
                fails.append(f"{key}/{m}: +{over:.1%} (limit {lim:.0%}), spread {max(st[m][1], st['off'][1]):.1%}")
    print("== idle daemon", flush=True)
    share, peak, secs = idle() if not only or "idle" in only else (0.0, 0.0, 0)
    if share > T["idle_cpu_share"]:
        fails.append(f"idle CPU {share:.2%} of a core (limit {T['idle_cpu_share']:.0%})")
    if peak > T["rss_mib"]:
        fails.append(f"RSS {peak:.0f} MiB (limit {T['rss_mib']} MiB)")
    kernel = os.uname().release
    o = ["# Overhead benchmarks (plan WP14)", "",
         f"Host: kernel {kernel}, {os.cpu_count()} CPUs, governor `{gov}`; {ROUNDS} rounds per benchmark, "
         "modes alternating within each round; times are medians; spread = (max - min) / median.",
         "Generated by `make bench` (bench/run.py) against bench/thresholds.toml." +
         (" QUICK MODE (development sizes, not a result)." if QUICK else "") +
         (f" PARTIAL RUN ({', '.join(only)}), not the full result." if only else ""), "",
         "| benchmark | mode | off (s) | with tracer (s) | overhead | limit | spread | ok |",
         "|---|---|---|---|---|---|---|---|"]
    for key, desc, m, base, med, over, lim, spread, ok in rows:
        o.append(f"| {desc} | {m} | {base:.3f} | {med:.3f} | {over:+.1%} | {lim:.0%} | {spread:.1%} | {'yes' if ok else 'NO'} |")
    o += ["", f"Idle daemon over {secs // 60} min: {share:.2%} of one core (limit {T['idle_cpu_share']:.0%}); "
          f"peak RSS {peak:.0f} MiB (limit {T['rss_mib']} MiB).", "",
          "Result: " + ("PASS" if not fails else "FAIL: " + "; ".join(fails)), ""]
    open(os.path.join(REPO, "docs", "BENCH.md"), "w").write("\n".join(o))
    print("\n".join(o))
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
