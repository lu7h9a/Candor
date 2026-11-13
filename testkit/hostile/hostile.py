#!/usr/bin/env python3
"""SysScope Glasshouse adversarial probes (plan 6.5, WP25). VM ONLY.

usage: hostile.py PROBE      (run inside a Glasshouse box by run_all.sh)

One probe per row of plan 6.5. Each tries what the row's attack would try,
prints CONTAINED or ESCAPED:<detail>, and writes the same text to
~/VERDICT.txt so the verdict comes back in the Glasshouse report (created
file preview). Nothing here is malware: the probes only test the sandbox's
own walls, and the bombs are bounded by the box's limits and the timeout.

Guard: refuses (exit 3) unless it is inside a Glasshouse box (hostname
"glasshouse", HOME=/home/victim, uid 1000) on a virtual machine (the CPU
reports the "hypervisor" flag). The marker file /etc/sysscope-test-vm and
DMI are not visible inside the box; run_all.sh checks those before it
starts any probe.
"""
import ctypes
import errno
import os
import signal
import socket
import stat
import sys
import time

HOME = "/home/victim"


def guard():
    try:
        cpu = open("/proc/cpuinfo").read()
    except OSError:
        cpu = ""
    flags = set()
    for line in cpu.splitlines():
        if line.startswith("flags"):
            flags.update(line.split(":", 1)[1].split())
    ok = (socket.gethostname() == "glasshouse" and os.environ.get("HOME") == HOME
          and os.getuid() == 1000 and "hypervisor" in flags)
    if not ok:
        print("REFUSED: hostile probes run only inside a Glasshouse box in a VM", file=sys.stderr)
        sys.exit(3)


libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def sc(nr, *args):
    """Raw syscall; returns (ret, errno)."""
    ctypes.set_errno(0)
    a = [ctypes.c_long(x) if isinstance(x, int) else x for x in args]
    r = libc.syscall(ctypes.c_long(nr), *a)
    return r, ctypes.get_errno()


class Verdict:
    def __init__(self, name):
        self.name, self.escapes, self.notes = name, [], []

    def escaped(self, what):
        self.escapes.append(what)

    def note(self, what):
        self.notes.append(what)

    def done(self):
        head = "CONTAINED" if not self.escapes else "ESCAPED:" + self.escapes[0]
        body = "\n".join([head] + ["escape: " + e for e in self.escapes[1:]] + self.notes)
        print("%s %s" % (self.name, head))
        for n in self.notes:
            print("  " + n)
        write_verdict(body)


def write_verdict(text):
    # Printable ASCII only: the report shows a preview of printable files.
    text = "".join(c if 32 <= ord(c) < 127 or c == "\n" else "?" for c in text)[:250]
    with open(os.path.join(HOME, "VERDICT.txt"), "w") as f:
        f.write(text + "\n")


def in_child(fn):
    """Runs fn in a forked child; returns ('exit', code) or ('signal', n)."""
    pid = os.fork()
    if pid == 0:
        try:
            fn()
        finally:
            os._exit(0)
    _, st = os.waitpid(pid, 0)
    if os.WIFSIGNALED(st):
        return ("signal", os.WTERMSIG(st))
    return ("exit", os.WEXITSTATUS(st))


# ---- 1. kernel attack surface: high-risk syscalls -------------------------
DENIED = {  # name: (nr, args)
    "bpf": (321, (0, 0, 0)), "perf_event_open": (298, (0, 0, -1, -1, 0)),
    "ptrace": (101, (16, 1, 0, 0)), "process_vm_readv": (310, (1, 0, 0, 0, 0, 0)),
    "userfaultfd": (323, (0,)), "io_uring_setup": (425, (1, 0)),
    "keyctl": (250, (0, 0, 0, 0, 0)), "add_key": (248, (0, 0, 0, 0, 0)),
    "request_key": (249, (0, 0, 0, 0)), "mount": (165, (0, 0, 0, 0, 0)),
    "umount2": (166, (0, 0)), "pivot_root": (155, (0, 0)), "chroot": (161, (0,)),
    "open_tree": (428, (-1, 0, 0)), "move_mount": (429, (-1, 0, -1, 0, 0)),
    "fsopen": (430, (0, 0)), "fsmount": (432, (-1, 0, 0)), "fspick": (433, (-1, 0, 0)),
    "unshare": (272, (0x10000000,)), "setns": (308, (-1, 0)),
    "kexec_load": (246, (0, 0, 0, 0)), "init_module": (175, (0, 0, 0)),
    "finit_module": (313, (-1, 0, 0)), "delete_module": (176, (0, 0)),
    "open_by_handle_at": (304, (-1, 0, 0)), "name_to_handle_at": (303, (-1, 0, 0, 0, 0)),
    "swapon": (167, (0, 0)), "reboot": (169, (0, 0, 0, 0)),
    "settimeofday": (164, (0, 0)), "clock_settime": (227, (0, 0)),
    "adjtimex": (159, (0,)), "acct": (163, (0,)), "iopl": (172, (3,)),
    "ioperm": (173, (0, 1, 1)), "modify_ldt": (154, (0, 0, 0)),
    "syslog": (103, (3, 0, 0)), "kcmp": (312, (1, 1, 0, 0, 0)),
    "personality(READ_IMPLIES_EXEC)": (135, (0x0400000,)),
    "process_vm_writev": (311, (1, 0, 0, 0, 0, 0)), "io_uring_enter": (426, (-1, 0, 0, 0, 0, 0)),
    "io_uring_register": (427, (-1, 0, 0, 0)), "fsconfig": (431, (-1, 0, 0, 0, 0)),
    "mount_setattr": (442, (-1, 0, 0, 0, 0)), "kexec_file_load": (320, (-1, -1, 0, 0, 0)),
    "swapoff": (168, (0,)), "clock_adjtime": (305, (0, 0)), "quotactl": (179, (0, 0, 0, 0)),
    "quotactl_fd": (443, (-1, 0, 0, 0)), "vhangup": (153, ()), "lookup_dcookie": (212, (0, 0, 0)),
    "clone(CLONE_NEWNS)": (56, (0x00020000 | 17, 0, 0, 0, 0)),
    "clone(CLONE_NEWNET)": (56, (0x40000000 | 17, 0, 0, 0, 0)),
    "clone(CLONE_NEWPID)": (56, (0x20000000 | 17, 0, 0, 0, 0)),
    "clone(CLONE_NEWUSER)": (56, (0x10000000 | 17, 0, 0, 0, 0)),
}


def seccomp_status(v):
    """EPERM alone does not prove the filter (the kernel refuses many of
    these to an unprivileged user anyway): the filters must be installed."""
    st = dict(l.split(":", 1) for l in open("/proc/self/status").read().splitlines() if ":" in l)
    mode = st.get("Seccomp", "").strip()
    filters = st.get("Seccomp_filters", "").strip()
    if mode != "2":
        v.escaped("Seccomp mode is %r, not 2 (filter)" % mode)
    if filters and int(filters) < 3:
        v.escaped("only %s seccomp filters installed, expected 3" % filters)
    v.note("Seccomp %s, filters %s" % (mode, filters or "n/a"))


def probe_syscalls():
    v = Verdict("syscalls")
    seccomp_status(v)
    for name, (nr, args) in DENIED.items():
        r, e = sc(nr, *args)
        if r == 0 and name.startswith("clone"):
            os._exit(0)  # a child was created: it leaves at once
        if e != errno.EPERM:
            v.escaped("%s reached the kernel (ret %d, %s)" % (name, r, errno.errorcode.get(e, e)))
    r, e = sc(435, 0, 0)  # clone3 must say ENOSYS so libc falls back to clone
    if e != errno.ENOSYS:
        v.escaped("clone3 returned %s, expected ENOSYS" % errno.errorcode.get(e, e))
    # x32 ABI: getpid with the x32 bit must kill the process.
    how = in_child(lambda: sc(0x40000000 | 39))
    if how != ("signal", signal.SIGSYS):
        v.escaped("x32 syscall not killed (%s)" % (how,))
    # i386 ABI via int 0x80 (getpid): the arch check must kill the process.
    def int80():
        import mmap
        code = bytes([0xB8, 0x14, 0, 0, 0, 0xCD, 0x80, 0xC3])  # mov eax,20; int 0x80; ret
        m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        m.write(code)
        addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
        ctypes.CFUNCTYPE(ctypes.c_int)(addr)()
    how = in_child(int80)
    if how != ("signal", signal.SIGSYS):
        v.escaped("i386 int 0x80 not killed (%s)" % (how,))
    v.note("%d syscalls refused, x32 and i386 killed" % len(DENIED))
    v.done()


# ---- 2. read host files ----------------------------------------------------
def probe_hostfiles():
    v = Verdict("hostfiles")
    top = sorted(os.listdir("/"))
    allowed = {"bin", "dev", "etc", "home", "lib", "lib64", "proc", "run", "sample", "sbin", "tmp", "usr", "var"}
    extra = [d for d in top if d not in allowed]
    if extra:
        v.escaped("unexpected top-level entries: %s" % extra)
    for p in ["/root", "/boot", "/sys", "/var/lib/sysscope", "/run/sysscope", "/run/sysscope-dev",
              "/etc/sysscope-test-vm", "/etc/ssh", "/etc/sudoers", "/home/debian", "/home/ubuntu"]:
        if os.path.lexists(p):
            v.escaped("host path visible: %s" % p)
    if sorted(os.listdir("/home")) != ["victim"]:
        v.escaped("/home lists %s" % os.listdir("/home"))
    passwd = open("/etc/passwd").read()
    if "sysscope" in passwd or len(passwd.splitlines()) != 2:
        v.escaped("/etc/passwd is not the synthetic one")
    for p in ["/proc/1/root/etc/hostname", "/proc/1/cwd/etc/passwd"]:
        try:
            data = open(p).read()
            if "glasshouse" not in data and "victim" not in data:
                v.escaped("host file through %s" % p)
        except OSError:
            pass
    v.note("residual (documented): /usr and /proc/{cpuinfo,meminfo,version} are visible")
    v.done()


# ---- 3. see or signal host processes ---------------------------------------
def probe_procs():
    v = Verdict("procs")
    pids = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())
    if len(pids) > 6:
        v.escaped("%d processes visible: %s" % (len(pids), pids[:10]))
    comm1 = open("/proc/1/comm").read().strip()
    if comm1 != "bwrap":
        v.escaped("pid 1 is %r, not bwrap" % comm1)
    # kill(-1, 0) reaches every process we may signal: only our own.
    killed = 0
    for pid in range(2, 4 * 1024 * 1024, 997):
        try:
            os.kill(pid, 0)
            if pid not in pids and pid != os.getpid():
                killed += 1
        except OSError:
            pass
    if killed:
        v.escaped("%d unseen pids accept signals" % killed)
    v.note("visible pids: %s" % pids)
    v.done()


# ---- 4. network --------------------------------------------------------------
def probe_network():
    v = Verdict("network")
    ifs = sorted(os.listdir("/proc/sys/net/ipv4/conf"))
    if [i for i in ifs if i not in ("all", "default", "lo")]:
        v.escaped("interfaces visible: %s" % ifs)
    for addr in [("10.0.2.2", 22), ("10.0.2.3", 53), ("1.1.1.1", 443), ("203.0.113.10", 80)]:
        try:
            socket.create_connection(addr, timeout=2).close()
            v.escaped("connected to %s:%d" % addr)
        except OSError:
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"x", ("10.0.2.3", 53))
        v.escaped("UDP datagram left the box")
    except OSError:
        pass
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        v.escaped("raw packet socket created")
    except OSError:
        pass
    v.done()


# ---- 5. X11, D-Bus, tracer socket, abstract sockets --------------------------
def probe_sockets():
    v = Verdict("sockets")
    paths = ["/tmp/.X11-unix/X0", "/run/dbus/system_bus_socket", "/run/user/1000/bus",
             "/run/sysscope/sysscope.sock", "/run/sysscope-dev/sysscope.sock",
             "/run/systemd/private", "/run/systemd/journal/socket"]
    abstract = ["\0sysscope-hostile-abstract", "\0/tmp/.X11-unix/X0", "\0/org/freedesktop/systemd1/private"]
    for p in paths + abstract:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(p)
            v.escaped("connected to %r" % p.replace("\0", "@"))
        except OSError:
            pass
        finally:
            s.close()
    v.note("run_all.sh listens on @sysscope-hostile-abstract outside the box")
    v.done()


# ---- 6. setuid binaries -------------------------------------------------------
def probe_setuid():
    import subprocess
    v = Verdict("setuid")
    st = open("/proc/self/status").read()
    if "NoNewPrivs:\t1" not in st:
        v.escaped("NoNewPrivs is not set")
    for line in st.splitlines():
        if line.startswith("Cap") and line.split()[1].strip("0"):
            v.escaped("capability set not empty: %s" % line)
    found = 0
    for d in ["/usr/bin", "/usr/sbin", "/usr/lib/dbus-1.0", "/usr/lib/openssh"]:
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            p = os.path.join(d, n)
            try:
                if not os.lstat(p).st_mode & stat.S_ISUID:
                    continue
            except OSError:
                continue
            found += 1
            # Start it and look at its effective uid while it waits for input.
            try:
                pr = subprocess.Popen([p], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
            except OSError:
                continue
            time.sleep(0.2)
            try:
                for line in open("/proc/%d/status" % pr.pid):
                    if line.startswith("Uid:") and line.split()[2] != "1000":
                        v.escaped("%s ran with euid %s" % (p, line.split()[2]))
            except OSError:
                pass
            pr.kill()
            pr.wait()
    r = subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", "/tmp"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if r.returncode == 0:
        v.escaped("mount (setuid) succeeded")
    v.note("%d setuid binaries tried" % found)
    v.done()


# ---- 7. nested user namespace ------------------------------------------------
def probe_userns():
    import subprocess
    v = Verdict("userns")
    if libc.unshare(0x10000000) == 0:
        v.escaped("unshare(CLONE_NEWUSER) succeeded")
    for flag, name in [(0x00020000, "NEWNS"), (0x40000000, "NEWNET"), (0x20000000, "NEWPID")]:
        if libc.unshare(flag) == 0:
            v.escaped("unshare(CLONE_%s) succeeded" % name)
    fd = os.open("/proc/self/ns/user", os.O_RDONLY)
    if libc.setns(fd, 0) == 0:
        v.escaped("setns succeeded")
    os.close(fd)
    for cmd in (["/usr/bin/unshare", "-U", "true"], ["/usr/bin/unshare", "-r", "true"],
                ["/usr/bin/bwrap", "--unshare-user", "--ro-bind", "/", "/", "true"]):
        if os.path.exists(cmd[0]):
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                v.escaped("%s succeeded" % " ".join(cmd))
    v.done()


# ---- 8. TIOCSTI / terminal ---------------------------------------------------
def probe_tiocsti():
    import fcntl
    import termios
    v = Verdict("tiocsti")
    for fd in (0, 1, 2):
        try:
            fcntl.ioctl(fd, termios.TIOCSTI, b"x")
            v.escaped("TIOCSTI worked on fd %d" % fd)
        except OSError:
            pass
        if os.isatty(fd):
            v.escaped("fd %d is a terminal" % fd)
    try:
        t = os.open("/dev/tty", os.O_RDWR)
        try:
            fcntl.ioctl(t, termios.TIOCSTI, b"x")
            v.escaped("TIOCSTI worked on /dev/tty")
        except OSError:
            pass
        os.close(t)
        v.escaped("/dev/tty could be opened")
    except OSError:
        pass
    if os.getsid(0) != os.getpid() and os.getsid(0) == 1:
        v.note("session leader: pid 1 (bwrap --new-session)")
    v.done()


# ---- 9. resource bombs (run_all.sh judges: timeout, responsiveness, leftovers) -
def probe_forkbomb():
    write_verdict("CONTAINED\nforkbomb started; run_all.sh checks the guest stayed responsive")
    print("forkbomb: starting", flush=True)
    while True:
        try:
            os.fork()
        except OSError:
            time.sleep(0.01)


def probe_membomb():
    write_verdict("CONTAINED\nmembomb started; run_all.sh checks the OOM kill and responsiveness")
    print("membomb: starting", flush=True)
    hog = []
    while True:
        hog.append(bytearray(64 * 1024 * 1024))
        for i in range(0, len(hog[-1]), 4096):
            hog[-1][i] = 1


def probe_cpuhog():
    write_verdict("CONTAINED\ncpuhog started; run_all.sh checks the timeout and responsiveness")
    for _ in range(7):
        if os.fork() == 0:
            break
    while True:
        pass


# ---- 10. disk fill -------------------------------------------------------------
def probe_diskfill():
    v = Verdict("diskfill")
    write_verdict("CONTAINED\ndiskfill running")
    big = os.path.join(HOME, "fill")
    os.makedirs(big, exist_ok=True)
    total, n, why = 0, 0, ""
    chunk = b"\0" * (1 << 20)
    while total < (2 << 30):
        try:
            with open(os.path.join(big, "f%04d" % n), "wb") as f:
                for _ in range(200):
                    f.write(chunk)
                    total += len(chunk)
        except OSError as e:
            why = errno.errorcode.get(e.errno, str(e.errno))
            break
        n += 1
    if total >= (2 << 30):
        v.escaped("wrote 2 GiB without hitting a limit")
    v.note("wrote %d MiB before %s" % (total >> 20, why or "stopping"))
    # Free the space, then test the per-file limit on its own: a sparse
    # 300 MiB file needs no space, so only LimitFSIZE (256 MiB) can stop it.
    for name in os.listdir(big):
        os.unlink(os.path.join(big, name))
    old = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    try:
        with open(os.path.join(big, "huge"), "wb") as f:
            f.truncate(300 << 20)
        v.escaped("a 300 MiB file was allowed (LimitFSIZE is 256 MiB)")
    except OSError as e:
        v.note("300 MiB file refused: %s" % errno.errorcode.get(e.errno, e.errno))
    signal.signal(signal.SIGXFSZ, old)
    v.done()


# ---- 11. blind or flood the tracer ----------------------------------------
def probe_flood():
    v = Verdict("flood")
    p = os.path.join(HOME, "flood.tmp")
    open(p, "w").close()
    t = time.time()
    n = 0
    while time.time() - t < 6:
        for _ in range(1000):
            os.close(os.open(p, os.O_RDONLY))
        n += 1000
    # After exhausting its budget, fork: the child's Fork event may be
    # dropped. The child reads a decoy; run_all.sh checks the report still
    # shows that read (attribution survives a flood).
    pid = os.fork()
    if pid == 0:
        with open(os.path.join(HOME, ".ssh/known_hosts"), "rb") as f:
            f.read()
        os._exit(0)
    os.waitpid(pid, 0)
    v.note("%d opens in 6 s, then a child read ~/.ssh/known_hosts; run_all.sh checks drops, R008 and that read" % n)
    v.done()


# ---- 12. tamper with the tracer ----------------------------------------------
def probe_tamper():
    v = Verdict("tamper")
    seccomp_status(v)
    for name in ("bpf", "perf_event_open", "ptrace", "process_vm_readv"):
        nr, args = DENIED[name]
        r, e = sc(nr, *args)
        if e != errno.EPERM:
            v.escaped("%s not refused (%s)" % (name, errno.errorcode.get(e, e)))
    for p in ("/sys/fs/bpf", "/sys/kernel/debug", "/sys/kernel/tracing", "/proc/sys/kernel/bpf_stats_enabled"):
        try:
            if p.startswith("/proc"):
                with open(p, "w") as f:
                    f.write("0")
                v.escaped("wrote %s" % p)
            elif os.path.exists(p):
                v.escaped("%s visible" % p)
        except OSError:
            pass
    for pid in sorted(int(x) for x in os.listdir("/proc") if x.isdigit()):
        try:
            if "sysscoped" in open("/proc/%d/comm" % pid).read():
                v.escaped("daemon visible as pid %d" % pid)
        except OSError:
            pass
    v.done()


# ---- 13. core dump to a host root helper -------------------------------------
def probe_coredump():
    import resource
    v = Verdict("coredump")
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        v.escaped("RLIMIT_CORE could be raised")
    except (ValueError, OSError):
        pass
    v.note("RLIMIT_CORE soft %s hard %s; run_all.sh checks the host core handler never ran" % (soft, hard))
    write_verdict("CONTAINED\ncrashing now")
    v.done()
    in_child(lambda: os.kill(os.getpid(), signal.SIGSEGV))
    os.kill(os.getpid(), signal.SIGABRT)


# ---- 14. hostile files for the host's differ ----------------------------------
def probe_torture():
    v = Verdict("torture")
    write_verdict("CONTAINED\ntorture tree being built; run_all.sh checks the differ")
    d = os.path.join(HOME, "torture")
    os.makedirs(d, exist_ok=True)
    os.symlink("/etc/shadow", os.path.join(d, "shadow-link"))
    os.symlink("/", os.path.join(d, "root-link"))
    os.mkfifo(os.path.join(d, "fifo"))
    for name in ("sda", "null", "tty0", "mem", "kmsg"):
        open(os.path.join(d, name), "w").close()
    for name in ("\x1b]0;pwned\x07title", "\x1b[2J\x1b[Hclear", "rtl-‮gnp.exe", "new\nline",
                 "tab\there", "bell\x07", "nul-free-\x7f-del", "\udcff-invalid-utf8"):
        try:
            open(os.path.join(d, name).encode("utf-8", "surrogateescape"), "w").write("x")
        except OSError:
            pass
    # A ~10 000 character path (single names are limited to 255 bytes).
    deep = d
    while len(deep) < 10000:
        deep = os.path.join(deep, "d" * 200)
        try:
            os.mkdir(deep)
        except OSError:
            break
    try:
        open(os.path.join(deep, "end"), "w").write("deep")
    except OSError:
        pass
    # 1 GiB sparse (LimitFSIZE refuses it), then the largest allowed one.
    for size in (1 << 30, (256 << 20) - 1):
        try:
            with open(os.path.join(d, "sparse"), "wb") as f:
                f.truncate(size)
            v.note("sparse file of %d MiB" % (size >> 20))
            break
        except OSError:
            continue
    # Hard link to a decoy (same inode, second name).
    try:
        os.link(os.path.join(HOME, "passwords.txt"), os.path.join(d, "hardlink"))
    except OSError:
        pass
    # 20 000 long non-UTF-8 names (inflate the differ's output 5x).
    longn = os.path.join(d, "long").encode()
    os.makedirs(longn, exist_ok=True)
    for i in range(20000):
        open(longn + b"/" + b"\xff" * 240 + b"%08d" % i, "w").close()
    # A 64-deep chain of 255-byte names, with files at the bottom.
    deep2 = os.path.join(d, "deep64")
    os.makedirs(deep2, exist_ok=True)
    fd = os.open(deep2, os.O_RDONLY)
    for _ in range(64):
        os.mkdir("e" * 255, dir_fd=fd)
        nfd = os.open("e" * 255, os.O_RDONLY, dir_fd=fd)
        os.close(fd)
        fd = nfd
    for i in range(500):
        os.close(os.open("f%04d" % i, os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=fd))
    os.close(fd)
    # Hide things from the differ: unreadable directories and a decoy.
    os.makedirs(os.path.join(d, "hidden"), exist_ok=True)
    open(os.path.join(d, "hidden", "payload"), "w").write("x")
    os.chmod(os.path.join(d, "hidden"), 0)
    os.chmod(os.path.join(HOME, "Documents"), 0)
    os.chmod(os.path.join(HOME, "wallet.dat"), 0)
    many = os.path.join(d, "many")
    os.makedirs(many, exist_ok=True)
    for i in range(100000):
        open(os.path.join(many, "f%06d" % i), "w").close()
    v.note("built 100000 files, links, a fifo, hostile names, a deep path")
    v.done()


# ---- 15. persisting after the run -------------------------------------------
def probe_persist():
    v = Verdict("persist")
    if os.fork() == 0:
        os.setsid()
        if os.fork() == 0:
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.chdir("/")
            time.sleep(3600)
        os._exit(0)
    for p in ("/tmp/persist", "/var/persist", os.path.join(HOME, ".config/autostart/x.desktop")):
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write("x")
        except OSError:
            pass
    v.note("left a double-forked, setsid, SIGTERM-ignoring sleeper; run_all.sh checks nothing survives")
    v.done()


# ---- 16. inherited file descriptors ------------------------------------------
def probe_fds():
    v = Verdict("fds")
    fds = sorted(int(x) for x in os.listdir("/proc/self/fd"))
    extra = []
    for fd in fds:
        if fd in (0, 1, 2):
            continue
        try:
            target = os.readlink("/proc/self/fd/%d" % fd)
        except OSError:
            continue  # the listing's own descriptor is already closed
        extra.append("%d->%s" % (fd, target))
    if extra:
        v.escaped("inherited descriptors: %s" % extra)
    v.note("fds: %s" % fds)
    v.done()


# ---- 17/18. documented residuals --------------------------------------------
def probe_detect():
    v = Verdict("detect")
    v.note("residual (accepted, documented): the box is detectable: hostname %s, HOME %s, pid 1 %s"
           % (socket.gethostname(), HOME, open("/proc/1/comm").read().strip()))
    v.done()


def probe_sidechannel():
    v = Verdict("sidechannel")
    v.note("residual (accepted, documented): CPU side channels are not mitigated by Glasshouse")
    v.done()


PROBES = {
    "syscalls": probe_syscalls, "hostfiles": probe_hostfiles, "procs": probe_procs,
    "network": probe_network, "sockets": probe_sockets, "setuid": probe_setuid,
    "userns": probe_userns, "tiocsti": probe_tiocsti, "forkbomb": probe_forkbomb,
    "membomb": probe_membomb, "cpuhog": probe_cpuhog, "diskfill": probe_diskfill,
    "flood": probe_flood, "tamper": probe_tamper, "coredump": probe_coredump,
    "torture": probe_torture, "persist": probe_persist, "fds": probe_fds,
    "detect": probe_detect, "sidechannel": probe_sidechannel,
}

if __name__ == "__main__":
    guard()
    if len(sys.argv) != 2 or sys.argv[1] not in PROBES:
        print("usage: hostile.py PROBE (%s)" % " ".join(PROBES), file=sys.stderr)
        sys.exit(2)
    PROBES[sys.argv[1]]()
