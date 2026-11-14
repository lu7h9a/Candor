//! `sysscope-glasshouse`: the Glasshouse helper (plan 6.1, 6.2, WP23).
//!
//! Glasshouse is a behaviour-demonstration sandbox, not a malware
//! containment system: it shares this computer's kernel.
//!
//! Subcommands:
//! - `prepare RUN_DIR` (root): decoys + manifest, synthetic /etc, seccomp
//!   filter files, ownership for the sandbox user.
//! - `stage2 RUN_DIR` (as `sysscope-box`, inside a systemd transient unit):
//!   waits on RUN_DIR/go (a FIFO), then execs bubblewrap with the 6.2
//!   arguments and the three seccomp filters. Name and arguments come from
//!   RUN_DIR/job.json, never from the command line.
//! - `run RUN_ID` (root, started by the daemon through `systemd-run --pipe`):
//!   one run of plan 6.1 steps 2-7, talking to the daemon with one JSON
//!   object per line (sysscope_proto::helper).
//! - `diff RUN_DIR` (as `sysscope-box`, started by `run`): reads the
//!   manifest and baseline on stdin, prints the differ result.
//! - `run-local [--calibrate] SAMPLE [ARGS...]` (root, without the daemon):
//!   the same run with a local stand-in for the daemon. `--calibrate` drops
//!   the seccomp filters and runs bubblewrap under `strace -f -c` so a test
//!   can count the box's opens independently (never used by the daemon).
//!   Exit code 4 and "Glasshouse unavailable: <reason>" if this system
//!   cannot run Glasshouse.
//! - `availability`: prints "available" or "unavailable: <reason>".
#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use sysscope_glasshouse::{decoys, differ, report, seccomp};
use sysscope_proto::helper::{GhJob, HelperIn, HelperOut};
use sysscope_proto::{BStr, GhState};

const BOX_USER: &str = "sysscope-box";
const RUNS: &str = "/var/lib/sysscope/glasshouse";

/// Files copied from the host /etc into the synthetic /etc (plan 6.2).
const ETC_COPY: &[&str] = &[
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    "alternatives",
    "ssl/certs",
    "nsswitch.conf",
    "localtime",
];

fn uid_gid_of(user: &str) -> Result<(u32, u32)> {
    let text = std::fs::read_to_string("/etc/passwd")?;
    for l in text.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.first() == Some(&user)
            && let (Some(u), Some(g)) = (f.get(2), f.get(3))
        {
            return Ok((u.parse()?, g.parse()?));
        }
    }
    bail!("user {user} does not exist (install packaging/sysusers/sysscope.conf)")
}

/// Copies a file, directory tree or symlink (symlinks stay symlinks).
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        std::os::unix::fs::symlink(std::fs::read_link(src)?, dst)?;
    } else if meta.is_dir() {
        std::fs::create_dir_all(dst)?;
        for e in std::fs::read_dir(src)? {
            let e = e?;
            copy_tree(&e.path(), &dst.join(e.file_name()))?;
        }
    } else if meta.is_file() {
        std::fs::copy(src, dst)?;
    }
    Ok(())
}

fn chown_tree(p: &Path, uid: u32, gid: u32) -> Result<()> {
    let ids = (
        Some(rustix::fs::Uid::from_raw(uid)),
        Some(rustix::fs::Gid::from_raw(gid)),
    );
    rustix::fs::chownat(
        rustix::fs::CWD,
        p,
        ids.0,
        ids.1,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )?;
    if std::fs::symlink_metadata(p)?.is_dir() {
        for e in std::fs::read_dir(p)? {
            chown_tree(&e?.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// prepare: decoys, manifest, synthetic /etc, seccomp files.
fn prepare(run: &Path) -> Result<()> {
    let (box_uid, box_gid) = uid_gid_of(BOX_USER)?;
    let manifest = decoys::generate(run, None)?;
    decoys::write_manifest(run, &manifest)?;
    // An ordinary dotfile a real home has; not a decoy, but in the baseline
    // so a change to it is reported (and writing it is not a "new file").
    std::fs::write(run.join("home/.bashrc"), "# ~/.bashrc\nalias ll='ls -l'\n")?;
    let base = differ::baseline(run, &manifest);
    write_private(&run.join("baseline.json"), &serde_json::to_vec(&base)?)?;
    let etc = run.join("etc");
    std::fs::create_dir_all(&etc)?;
    for name in ETC_COPY {
        let src = Path::new("/etc").join(name);
        if std::fs::symlink_metadata(&src).is_ok() {
            if let Some(parent) = etc.join(name).parent() {
                std::fs::create_dir_all(parent)?;
            }
            copy_tree(&src, &etc.join(name)).with_context(|| format!("copying /etc/{name}"))?;
        }
    }
    let generated: [(&str, &str); 5] = [
        (
            "passwd",
            "root:x:0:0:root:/root:/usr/sbin/nologin\nvictim:x:1000:1000:Victim:/home/victim:/bin/sh\n",
        ),
        ("group", "root:x:0:\nvictim:x:1000:\n"),
        ("hostname", "glasshouse\n"),
        ("hosts", "127.0.0.1 localhost glasshouse\n::1 localhost\n"),
        ("resolv.conf", ""),
    ];
    for (name, content) in generated {
        std::fs::write(etc.join(name), content)?;
    }
    for (i, p) in seccomp::all_programs()?.iter().enumerate() {
        std::fs::write(run.join(format!("seccomp-{i}.bpf")), seccomp::to_bytes(p))?;
    }
    // The sample and its home are written by uid 1000 inside the box, which
    // is sysscope-box outside. Everything else stays root-owned, read-only.
    chown_tree(&run.join("home"), box_uid, box_gid)?;
    rustix::fs::chown(run, None, Some(rustix::fs::Gid::from_raw(box_gid)))?;
    std::fs::set_permissions(run, std::fs::Permissions::from_mode(0o750))?;
    Ok(())
}

/// Writes a root-only file (0600).
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

/// `--symlink usr/X /X` for every /usr directory that exists (merged /usr).
fn usr_symlinks() -> Vec<String> {
    let mut a = Vec::new();
    for (link, target) in [
        ("/bin", "usr/bin"),
        ("/sbin", "usr/sbin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
    ] {
        if std::fs::symlink_metadata(Path::new("/").join(target)).is_ok() {
            a.extend(["--symlink".to_string(), target.into(), link.into()]);
        }
    }
    a
}

/// The bubblewrap command line of plan 6.2 (seccomp fds appended by stage2).
pub fn bwrap_args(run: &Path, sample_name: &str) -> Vec<String> {
    let r = |p: &str| run.join(p).display().to_string();
    let mut a: Vec<String> = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--hostname",
        "glasshouse",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/home/victim",
        "--setenv",
        "USER",
        "victim",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--uid",
        "1000",
        "--gid",
        "1000",
        "--ro-bind",
        "/usr",
        "/usr",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.extend(usr_symlinks());
    a.extend([
        "--ro-bind".into(),
        r("etc"),
        "/etc".into(),
        "--bind".into(),
        r("home"),
        "/home/victim".into(),
        "--ro-bind".into(),
        r("sample"),
        format!("/sample/{sample_name}"),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--tmpfs".into(),
        "/run".into(),
        "--tmpfs".into(),
        "/var".into(),
        "--chdir".into(),
        "/home/victim".into(),
    ]);
    a
}

/// Reads and checks a job file.
fn read_job(path: &Path) -> Result<GhJob> {
    let text = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let job: GhJob = serde_json::from_slice(&text).context("job file")?;
    if !valid_name(&job.name) {
        bail!("bad sample name in the job file");
    }
    if !(1..=600).contains(&job.timeout_s) {
        bail!("timeout must be 1..600 s");
    }
    if job.args.len() > 256 || job.args.iter().any(|a| a.as_bytes().len() > 4096) {
        bail!("too many or too long arguments");
    }
    Ok(job)
}

/// Sample names inside the box: [A-Za-z0-9._-], 1..64, not starting with '.'.
pub fn valid_name(n: &str) -> bool {
    (1..=64).contains(&n.len())
        && !n.starts_with('.')
        && n.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// stage2: runs as sysscope-box in the transient unit.
fn stage2(run: &Path) -> Result<()> {
    let job = read_job(&run.join("job.json"))?;
    let sample_name = job.name.as_str();
    let args: Vec<std::ffi::OsString> = job
        .args
        .iter()
        .map(|a| std::os::unix::ffi::OsStringExt::from_vec(a.as_bytes().to_vec()))
        .collect();
    // Wait until the helper has registered our cgroup for tracing.
    let mut go = std::fs::File::open(run.join("go")).context("opening the go FIFO")?;
    let mut b = [0u8; 1];
    std::io::Read::read(&mut go, &mut b)?;
    let mut cmd = if job.calibrate {
        // Calibration only (run-local --calibrate): log every successful
        // open of the box with strace, which the seccomp filter would refuse
        // (ptrace). One line per open, so O_PATH opens (which never reach
        // security_file_open: they give no access to file data) can be told
        // apart from data opens.
        let mut c = Command::new("/usr/bin/strace");
        c.args([
            "-f",
            "-qq",
            "-e",
            "trace=open,openat,openat2,creat",
            "-e",
            "status=successful",
            "-o",
        ])
        .arg(run.join("strace.out"))
        .arg("/usr/bin/bwrap");
        c
    } else {
        Command::new("/usr/bin/bwrap")
    };
    cmd.args(bwrap_args(run, sample_name));
    // systemd starts us with only fds 0-2; the seccomp files are the only
    // descriptors we pass on (CLOEXEC cleared on exactly those).
    let mut keep = Vec::new();
    for i in 0..3 {
        if job.calibrate {
            break;
        }
        let f = std::fs::File::open(run.join(format!("seccomp-{i}.bpf")))?;
        rustix::io::fcntl_setfd(&f, rustix::io::FdFlags::empty())?;
        cmd.args([
            "--add-seccomp-fd",
            &std::os::fd::AsRawFd::as_raw_fd(&f).to_string(),
        ]);
        keep.push(f);
    }
    cmd.arg(format!("/sample/{sample_name}")).args(args);
    let e = cmd.exec(); // only returns on error
    bail!("exec bwrap: {e}")
}

/// Unit properties of plan 6.2 (fail closed if systemd rejects any).
fn unit_properties(run: &Path, timeout_s: u32) -> Vec<String> {
    let mut p: Vec<String> = [
        "User=sysscope-box",
        "NoNewPrivileges=yes",
        "MemoryMax=1G",
        "MemorySwapMax=0",
        "TasksMax=256",
        "CPUQuota=100%",
        // 1, not the plan's 0: with a piped kernel.core_pattern the kernel
        // ignores a limit of 0 and runs the host's root core handler for
        // the box process (WP25 coredump probe, ESCAPED with 0). A limit of
        // exactly 1 aborts piped dumps, and is below the smallest ELF core
        // for file dumps; the box cannot raise it (hard limit, no caps).
        "LimitCORE=1",
        "LimitFSIZE=268435456",
        "LimitNOFILE=1024",
        "KillMode=control-group",
        "StandardInput=null",
        "OOMPolicy=kill",
        "CollectMode=inactive-or-failed",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    p.push(format!("RuntimeMaxSec={}", timeout_s + 5));
    p.push(format!(
        "StandardOutput=file:{}",
        run.join("stdout").display()
    ));
    p.push(format!(
        "StandardError=file:{}",
        run.join("stderr").display()
    ));
    p
}

/// Whether Glasshouse can run here: a real bubblewrap start as the sandbox
/// user (nothing is assumed from distro names). Never changes any setting.
pub fn availability() -> std::result::Result<(), String> {
    let (uid, gid) = uid_gid_of(BOX_USER).map_err(|e| e.to_string())?;
    if !Path::new("/usr/bin/bwrap").exists() {
        return Err("bubblewrap (/usr/bin/bwrap) is not installed".into());
    }
    let out = Command::new("/usr/bin/setpriv")
        .args([
            format!("--reuid={uid}"),
            format!("--regid={gid}"),
            "--clear-groups".into(),
            "--no-new-privs".into(),
        ])
        .args([
            "/usr/bin/bwrap",
            "--unshare-all",
            "--ro-bind",
            "/usr",
            "/usr",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ])
        // The same /bin, /lib, /lib64 symlinks the real sandbox gets.
        .args(usr_symlinks())
        .arg("/usr/bin/true")
        .output()
        .map_err(|e| format!("cannot run setpriv: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let mut why = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let restrict =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .unwrap_or_default();
    if restrict.trim() == "1" {
        why.push_str(" (kernel.apparmor_restrict_unprivileged_userns = 1: this system's AppArmor policy blocks unprivileged user namespaces; SysScope does not change that setting)");
    }
    let clone =
        std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone").unwrap_or_default();
    if clone.trim() == "0" {
        why.push_str(
            " (kernel.unprivileged_userns_clone = 0; SysScope does not change that setting)",
        );
    }
    Err(why)
}

/// The daemon side of a run, as the helper sees it.
trait Bridge {
    /// Sends one message to the daemon (or the local stand-in).
    fn send(&mut self, m: HelperOut);
    /// Waits up to `timeout` for a message; None on timeout.
    fn recv(&mut self, timeout: Duration) -> Option<HelperIn>;
}

/// The daemon over stdin/stdout (`systemd-run --pipe`).
struct DaemonBridge {
    rx: std::sync::mpsc::Receiver<HelperIn>,
}

impl DaemonBridge {
    fn new() -> DaemonBridge {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut lock = stdin.lock();
            loop {
                match sysscope_proto::read_line_bounded(&mut lock, 64 * 1024) {
                    Ok(Some(sysscope_proto::Line::Text(l))) => {
                        match serde_json::from_slice::<HelperIn>(&l) {
                            Ok(m) => {
                                if tx.send(m).is_err() {
                                    return;
                                }
                            }
                            Err(_) => {
                                eprintln!("sysscope-glasshouse: ignoring a malformed daemon line")
                            }
                        }
                    }
                    Ok(Some(sysscope_proto::Line::TooLong)) => {
                        eprintln!("sysscope-glasshouse: ignoring an over-long daemon line");
                    }
                    // The daemon went away: stop the run.
                    Ok(None) | Err(_) => {
                        let _ = tx.send(HelperIn::Cancel {});
                        return;
                    }
                }
            }
        });
        DaemonBridge { rx }
    }
}

impl Bridge for DaemonBridge {
    fn send(&mut self, m: HelperOut) {
        if let Ok(line) = serde_json::to_string(&m) {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
    }
    fn recv(&mut self, timeout: Duration) -> Option<HelperIn> {
        self.rx.recv_timeout(timeout).ok()
    }
}

/// Stand-in for the daemon in `run-local`: prints progress, says Go at once.
#[derive(Default)]
struct LocalBridge {
    go_pending: bool,
    diff: Option<HelperOut>,
}

impl Bridge for LocalBridge {
    fn send(&mut self, m: HelperOut) {
        match &m {
            HelperOut::Status { message, .. } => {
                eprintln!("glasshouse: {}", escape_lines(message.as_bytes()))
            }
            HelperOut::Need {
                cgroup_id,
                pid,
                run_dir,
                ..
            } => {
                eprintln!("glasshouse: box pid {pid} cgroup id {cgroup_id} run dir {run_dir}");
                self.go_pending = true;
            }
            HelperOut::Failed { message } => {
                eprintln!("glasshouse: {}", escape_lines(message.as_bytes()))
            }
            HelperOut::Diff { .. } | HelperOut::Ended {} => {}
        }
        if matches!(m, HelperOut::Diff { .. }) {
            self.diff = Some(m);
        }
    }
    fn recv(&mut self, timeout: Duration) -> Option<HelperIn> {
        if std::mem::take(&mut self.go_pending) {
            return Some(HelperIn::Go {});
        }
        std::thread::sleep(timeout);
        None
    }
}

/// What a finished run leaves for `run-local` to print.
struct Outcome {
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    strace: Vec<u8>,
}

/// Reads at most `max` bytes of a file (missing file = empty).
fn read_capped(p: &Path, max: u64) -> Vec<u8> {
    let mut v = Vec::new();
    if let Ok(f) = std::fs::File::open(p) {
        let _ = std::io::Read::read_to_end(&mut std::io::Read::take(f, max), &mut v);
    }
    v
}

fn kill_unit(unit: &str) {
    let _ = Command::new("/usr/bin/systemctl")
        .args(["kill", "--signal=SIGKILL", &format!("{unit}.service")])
        .status();
}

/// Main pid of a unit (0 while it is starting).
fn main_pid(unit: &str) -> u32 {
    Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "-p",
            "MainPID",
            "--value",
            &format!("{unit}.service"),
        ])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

/// Runs the differ as the sandbox user (never root) and returns its result.
fn run_differ(run: &Path, input: &differ::DiffInput) -> Result<differ::DiffOutput> {
    const MAX_OUT: u64 = 12 * 1024 * 1024; // below the daemon's helper line cap
    const MAX_TIME: Duration = Duration::from_secs(60); // the differ stops itself at 30 s
    let (uid, gid) = uid_gid_of(BOX_USER)?;
    let mut child = Command::new("/usr/bin/setpriv")
        .args([
            format!("--reuid={uid}"),
            format!("--regid={gid}"),
            "--clear-groups".into(),
            "--no-new-privs".into(),
        ])
        .arg(std::env::current_exe()?)
        .arg("diff")
        .arg(run)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("starting the differ")?;
    let body = serde_json::to_vec(input)?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(&body)?;
    }
    // Drained on its own thread so a large output can never block the
    // differ while this thread waits; anything over the cap is discarded.
    let so = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut over = false;
        if let Some(mut so) = so {
            let _ = std::io::Read::read_to_end(
                &mut std::io::Read::take(&mut so, MAX_OUT + 1),
                &mut out,
            );
            over = out.len() as u64 > MAX_OUT;
            let _ = std::io::copy(&mut so, &mut std::io::sink());
        }
        (out, over)
    });
    let deadline = Instant::now() + MAX_TIME;
    let st = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("the differ did not finish within {} s", MAX_TIME.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (out, over) = reader
        .join()
        .map_err(|_| anyhow::anyhow!("differ reader failed"))?;
    if over {
        bail!("the differ's result was larger than {} MiB", MAX_OUT >> 20);
    }
    if !st.success() {
        bail!("the differ failed ({st})");
    }
    serde_json::from_slice(&out).context("differ output")
}

/// One run (plan 6.1 steps 2-7) in `RUNS/<run_id>`. Sends Need/Status/Diff
/// through `bridge`; on error the caller sends Failed.
fn run_box(run_id: &str, job: &GhJob, sample: &Path, bridge: &mut dyn Bridge) -> Result<Outcome> {
    let run = PathBuf::from(RUNS).join(run_id);
    std::fs::create_dir_all(RUNS)?;
    std::fs::create_dir(&run).with_context(|| format!("creating {}", run.display()))?;
    let st = Command::new("/usr/bin/mount")
        .args([
            "-t",
            "tmpfs",
            "-o",
            "size=512m,nodev,nosuid,mode=0750",
            "tmpfs",
        ])
        .arg(&run)
        .status()?;
    if !st.success() {
        let _ = std::fs::remove_dir(&run);
        bail!("mounting the run tmpfs failed");
    }
    let result = run_in(&run, run_id, job, sample, bridge);
    let unmounted = Command::new("/usr/bin/umount")
        .arg(&run)
        .status()
        .is_ok_and(|s| s.success())
        || Command::new("/usr/bin/umount")
            .arg("--lazy")
            .arg(&run)
            .status()
            .is_ok_and(|s| s.success());
    if !unmounted || std::fs::remove_dir(&run).is_err() {
        eprintln!(
            "sysscope-glasshouse: could not remove the run directory {}",
            run.display()
        );
    }
    result
}

fn run_in(
    run: &Path,
    run_id: &str,
    job: &GhJob,
    sample: &Path,
    bridge: &mut dyn Bridge,
) -> Result<Outcome> {
    bridge.send(HelperOut::Status {
        state: GhState::Starting,
        message: "preparing the sandbox".into(),
    });
    prepare(run)?;
    let (box_uid, box_gid) = uid_gid_of(BOX_USER)?;
    std::fs::copy(sample, run.join("sample")).context("copying the sample")?;
    std::fs::set_permissions(run.join("sample"), std::fs::Permissions::from_mode(0o755))?;
    let job_path = run.join("job.json");
    std::fs::write(&job_path, serde_json::to_vec(job)?)?;
    rustix::fs::chown(&job_path, None, Some(rustix::fs::Gid::from_raw(box_gid)))?;
    std::fs::set_permissions(&job_path, std::fs::Permissions::from_mode(0o640))?;
    let box_owned = |p: &Path| {
        rustix::fs::chown(
            p,
            Some(rustix::fs::Uid::from_raw(box_uid)),
            Some(rustix::fs::Gid::from_raw(box_gid)),
        )
    };
    if job.calibrate {
        std::fs::write(run.join("strace.out"), b"")?;
        box_owned(&run.join("strace.out"))?;
    }
    let fifo = run.join("go");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )?;
    box_owned(&fifo)?;
    let unit = format!("sysscope-gh-{run_id}");
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new("/usr/bin/systemd-run");
    // Not --quiet: systemd-run then reports how the unit ended ("Finished
    // with result: ...", "Main processes terminated with: code=..."), which
    // is the only honest exit status (its own exit code is 1 for any
    // failure, e.g. an OOM kill).
    cmd.args(["--wait", "--unit", &unit, "--service-type=exec"]);
    for p in unit_properties(run, job.timeout_s) {
        cmd.args(["-p", &p]);
    }
    cmd.arg(&exe).arg("stage2").arg(run);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().context("systemd-run")?;
    // From here on every error path must stop the box: a helper that
    // returns early must not leave the unit (and stage2 holding the run dir).
    let r = (|| -> Result<Outcome> {
        // The unit's cgroup id is the inode of its cgroup directory.
        let cg = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}.service"));
        let mut cg_ino = None;
        let mut pid = 0;
        for _ in 0..200 {
            if cg_ino.is_none()
                && let Ok(m) = std::fs::metadata(&cg)
            {
                cg_ino = Some(m.ino());
            }
            if cg_ino.is_some() {
                pid = main_pid(&unit);
                if pid != 0 {
                    break;
                }
            }
            if let Ok(Some(st)) = child.try_wait() {
                bail!(
                    "the sandbox unit exited before starting (systemd-run status {st}); a required property may be unsupported"
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let (Some(cgroup_id), true) = (cg_ino, pid != 0) else {
            kill_unit(&unit);
            let _ = child.wait();
            bail!("the sandbox unit did not start");
        };
        let manifest: decoys::Manifest =
            serde_json::from_slice(&std::fs::read(run.join("manifest.json"))?)?;
        bridge.send(HelperOut::Need {
            cgroup_id,
            pid,
            run_dev: std::fs::metadata(run)?.dev(),
            run_dir: run.display().to_string(),
            decoys: differ::initial_status(&manifest),
        });
        match bridge.recv(Duration::from_secs(15)) {
            Some(HelperIn::Go {}) => {}
            other => {
                kill_unit(&unit);
                let _ = child.wait();
                let why = match other {
                    Some(HelperIn::Refuse { message }) => message,
                    Some(HelperIn::Cancel {}) => "cancelled".into(),
                    _ => "the daemon did not confirm that tracing is set up".into(),
                };
                bail!("not started: {why}");
            }
        }
        // Non-blocking: if stage2 already died there is no reader, and a
        // blocking open would wait forever (ENXIO instead).
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .context("the sandbox is no longer waiting to start")?
                .write_all(b"g")?;
        }
        bridge.send(HelperOut::Status {
            state: GhState::Running,
            message: "sample started".into(),
        });
        let deadline = Instant::now() + Duration::from_secs(u64::from(job.timeout_s));
        let (mut timed_out, mut cancelled) = (false, false);
        let mut killed_at: Option<Instant> = None;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if killed_at.is_none() && Instant::now() >= deadline {
                timed_out = true;
                kill_unit(&unit);
                killed_at = Some(Instant::now());
            }
            if let Some(HelperIn::Cancel {}) = bridge.recv(Duration::from_millis(100))
                && killed_at.is_none()
            {
                cancelled = true;
                kill_unit(&unit);
                killed_at = Some(Instant::now());
            }
            if killed_at.is_some_and(|t| t.elapsed() > Duration::from_secs(15)) {
                let _ = child.kill(); // systemd-run itself is stuck
            }
        };
        // KillMode=control-group: the unit is stopped only once every process
        // in it is gone, after which its cgroup directory is removed.
        let mut notes = Vec::new();
        let empty_by = Instant::now() + Duration::from_secs(10);
        while cg.exists() && Instant::now() < empty_by {
            std::thread::sleep(Duration::from_millis(50));
        }
        if cg.exists() {
            notes.push("the sandbox cgroup still existed 10 s after the run ended".to_string());
        }
        bridge.send(HelperOut::Ended {});
        bridge.send(HelperOut::Status {
            state: GhState::Running,
            message: "sample ended; comparing files".into(),
        });
        let baseline: Vec<differ::BaselineEntry> =
            serde_json::from_slice(&std::fs::read(run.join("baseline.json"))?)?;
        let d = run_differ(run, &differ::DiffInput { manifest, baseline })?;
        notes.extend(d.notes);
        let _ = status;
        let mut said = Vec::new();
        if let Some(mut e) = child.stderr.take() {
            let _ =
                std::io::Read::read_to_end(&mut std::io::Read::take(&mut e, 64 * 1024), &mut said);
        }
        let end = unit_end(&String::from_utf8_lossy(&said));
        let exit_code = if timed_out || cancelled {
            None
        } else {
            end.exit_code
        };
        if let Some(n) = end.note(timed_out || cancelled) {
            notes.push(n);
        }
        bridge.send(HelperOut::Diff {
            exit_code,
            timed_out,
            cancelled,
            decoys: d.decoys,
            created: d.created,
            notes,
        });
        Ok(Outcome {
            exit_code,
            stdout: read_capped(&run.join("stdout"), 1 << 20),
            stderr: read_capped(&run.join("stderr"), 1 << 20),
            strace: read_capped(&run.join("strace.out"), 1 << 20),
        })
    })();
    if r.is_err() {
        kill_unit(&unit);
        let _ = child.kill();
        let _ = child.wait();
    }
    r
}

/// How the box unit ended, from systemd-run's closing lines.
#[derive(Debug, Default, PartialEq)]
struct UnitEnd {
    result: String,
    code: String,
    status: String,
    exit_code: Option<i32>,
}

fn unit_end(text: &str) -> UnitEnd {
    let mut e = UnitEnd::default();
    for l in text.lines() {
        let l = l.trim();
        if let Some(r) = l.strip_prefix("Finished with result:") {
            e.result = r.trim().to_string();
        }
        if let Some(r) = l.strip_prefix("Main processes terminated with:") {
            // systemd 252: "code=exited/status=0", "code=killed/status=KILL",
            // "code=exited/status=3/NOTIMPLEMENTED"; systemd 260:
            // "code=exited, status=3/NOTIMPLEMENTED".
            let r = r.trim();
            if let Some(rest) = r.strip_prefix("code=") {
                let split = rest
                    .split_once("/status=")
                    .or_else(|| rest.split_once(", status="));
                if let Some((code, status)) = split {
                    e.code = code.trim().to_string();
                    e.status = status
                        .split('/')
                        .next()
                        .unwrap_or(status)
                        .trim()
                        .to_string();
                }
            }
        }
    }
    if e.code == "exited" {
        e.exit_code = e.status.parse().ok();
    }
    e
}

impl UnitEnd {
    /// A note when the sample did not simply exit (None for a plain exit or
    /// a run the helper itself stopped).
    fn note(&self, stopped_by_us: bool) -> Option<String> {
        if stopped_by_us || (self.code == "exited" && self.result == "success") {
            return None;
        }
        Some(match self.result.as_str() {
            "oom-kill" => "the sample was stopped by the 1 GiB memory limit (oom-kill)".into(),
            "timeout" => "the sample was stopped by the unit's runtime limit".into(),
            "" => "how the sample ended is unknown (systemd-run did not say)".into(),
            r if self.code.is_empty() => {
                format!("how the sample ended is unknown (unit result: {r})")
            }
            r if self.code == "exited" => {
                format!("the sample exited with code {} ({r})", self.status)
            }
            r => format!(
                "the sample was {} by signal {} ({r})",
                self.code, self.status
            ),
        })
    }
}

/// `run RUN_ID`: the daemon-driven run.
fn daemon_run(run_id: &str) -> Result<i32> {
    let mut b = DaemonBridge::new();
    if !valid_run_id(run_id) {
        b.send(HelperOut::Failed {
            message: "bad run id".into(),
        });
        return Ok(2);
    }
    if let Err(why) = availability() {
        b.send(HelperOut::Failed {
            message: format!("Glasshouse unavailable: {why}"),
        });
        return Ok(4);
    }
    let base = PathBuf::from(RUNS);
    let res = read_job(&base.join(format!("{run_id}.job.json")))
        .and_then(|job| run_box(run_id, &job, &base.join(format!("{run_id}.sample")), &mut b));
    match res {
        Ok(_) => Ok(0),
        Err(e) => {
            b.send(HelperOut::Failed {
                message: format!("{e:#}"),
            });
            Ok(1)
        }
    }
}

/// Run ids: [A-Za-z0-9-], 1..64.
fn valid_run_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

/// `diff RUN_DIR` (as sysscope-box): manifest + baseline on stdin.
fn diff_cmd(run: &Path) -> Result<i32> {
    if rustix::process::geteuid().is_root() {
        bail!("the differ never runs as root");
    }
    let mut body = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::io::stdin(), 64 << 20),
        &mut body,
    )?;
    let input: differ::DiffInput = serde_json::from_slice(&body).context("differ input")?;
    let out = differ::diff(run, &input, differ::Limits::default());
    println!("{}", serde_json::to_string(&out)?);
    Ok(0)
}

/// run-local: one run without the daemon.
fn run_local(sample: &Path, args: &[String], calibrate: bool) -> Result<i32> {
    if let Err(why) = availability() {
        eprintln!("Glasshouse unavailable: {why}");
        return Ok(4);
    }
    let id = format!(
        "local-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    let name = sample
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| valid_name(n))
        .unwrap_or_else(|| "sample".into());
    let job = GhJob {
        name,
        args: args.iter().map(|a| BStr::from(a.as_str())).collect(),
        timeout_s: 60,
        calibrate,
    };
    let mut b = LocalBridge::default();
    let o = run_box(&id, &job, sample, &mut b)?;
    // Sample output is untrusted: printed escaped (I10).
    println!("--- sample stdout ---\n{}", escape_lines(&o.stdout));
    println!("--- sample stderr ---\n{}", escape_lines(&o.stderr));
    if calibrate {
        println!("--- strace ---\n{}", escape_lines(&o.strace));
    }
    if let Some(HelperOut::Diff {
        decoys,
        created,
        notes,
        ..
    }) = &b.diff
    {
        let r = sysscope_proto::GhReport {
            run_id: id.clone(),
            sample: BStr::from(job.name.as_str()),
            args: job.args.clone(),
            timeout_s: job.timeout_s,
            started_ts: 0,
            ended_ts: 0,
            exit_code: o.exit_code,
            timed_out: false,
            decoys: decoys.clone(),
            created: created.clone(),
            timeline: Vec::new(),
            connections: Vec::new(),
            children: Vec::new(),
            findings: Vec::new(),
            loss: sysscope_proto::Loss::default(),
            limitation: report::LIMITATION.into(),
            notes: notes.clone(),
        };
        eprintln!(
            "--- differ (no trace without the daemon) ---\n{}",
            report::render_text(&r)
        );
    }
    Ok(o.exit_code.unwrap_or(-1))
}

/// Escapes untrusted bytes line by line, keeping real newlines readable (I10).
fn escape_lines(b: &[u8]) -> String {
    b.split(|&c| c == b'\n')
        .map(|l| sysscope_core::display::safe(&sysscope_proto::BStr(l.to_vec())))
        .collect::<Vec<_>>()
        .join("\n")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("prepare") => args
            .get(1)
            .map(PathBuf::from)
            .context("prepare RUN_DIR")
            .and_then(|r| prepare(&r))
            .map(|()| 0),
        Some("stage2") => match args.get(1) {
            Some(run) => stage2(Path::new(run)).map(|()| 0),
            None => Err(anyhow::anyhow!("stage2 RUN_DIR")),
        },
        Some("run") => match args.get(1) {
            Some(id) => daemon_run(id),
            None => Err(anyhow::anyhow!("run RUN_ID")),
        },
        Some("diff") => match args.get(1) {
            Some(run) => diff_cmd(Path::new(run)),
            None => Err(anyhow::anyhow!("diff RUN_DIR")),
        },
        Some("availability") => match availability() {
            Ok(()) => {
                println!("available");
                Ok(0)
            }
            Err(why) => {
                println!("unavailable: {}", escape_lines(why.as_bytes()));
                Ok(4)
            }
        },
        Some("run-local") => {
            let calibrate = args.get(1).map(String::as_str) == Some("--calibrate");
            let rest = args.get(if calibrate { 2 } else { 1 }..).unwrap_or(&[]);
            match rest.split_first() {
                Some((sample, a)) => run_local(Path::new(sample), a, calibrate),
                None => Err(anyhow::anyhow!("run-local [--calibrate] SAMPLE [ARGS]")),
            }
        }
        _ => Err(anyhow::anyhow!(
            "usage: sysscope-glasshouse prepare RUN_DIR | stage2 RUN_DIR | run RUN_ID | diff RUN_DIR | run-local [--calibrate] SAMPLE [ARGS] | availability"
        )),
    };
    match res {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("sysscope-glasshouse: {e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_end_is_read_from_systemd_run() {
        let ok = unit_end(
            "Running as unit: x.service\nFinished with result: success\nMain processes terminated with: code=exited/status=0\nService runtime: 213ms\n",
        );
        assert_eq!((ok.exit_code, ok.note(false)), (Some(0), None));
        let oom = unit_end(
            "Finished with result: oom-kill\nMain processes terminated with: code=killed/status=KILL\n",
        );
        assert_eq!(oom.exit_code, None);
        assert_eq!(
            oom.note(false).as_deref(),
            Some("the sample was stopped by the 1 GiB memory limit (oom-kill)")
        );
        let fail = unit_end(
            "Finished with result: exit-code\nMain processes terminated with: code=exited/status=3/NOTIMPLEMENTED\n",
        );
        assert_eq!(fail.exit_code, Some(3));
        assert_eq!(
            fail.note(false).as_deref(),
            Some("the sample exited with code 3 (exit-code)")
        );
        assert_eq!(oom.note(true), None);
        // systemd 260 wording.
        let new = unit_end(
            "          Finished with result: exit-code\nMain processes terminated with: code=exited, status=3/NOTIMPLEMENTED\n",
        );
        assert_eq!(new.exit_code, Some(3));
        let ok260 = unit_end(
            "Finished with result: success\nMain processes terminated with: code=exited, status=0/SUCCESS\n",
        );
        assert_eq!((ok260.exit_code, ok260.note(false)), (Some(0), None));
        let oom260 = unit_end(
            "Finished with result: oom-kill\nMain processes terminated with: code=killed, status=9/KILL\n",
        );
        assert_eq!(oom260.exit_code, None);
        assert!(valid_name("fake_malware.py") && !valid_name(".x") && !valid_name("a/b"));
    }
}
