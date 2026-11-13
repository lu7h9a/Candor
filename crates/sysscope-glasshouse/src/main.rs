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
//!   arguments and the three seccomp filters.
//! - `run-local SAMPLE [ARGS...]` (root, test path before the daemon
//!   integration): makes a tmpfs run dir, prepares it, starts the unit,
//!   reports its cgroup id, releases stage2, waits, cleans up. Exit code 4
//!   and "Glasshouse unavailable: <reason>" if this system cannot run it.
//! - `availability`: prints "available" or "unavailable: <reason>".
#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use sysscope_glasshouse::{decoys, seccomp};

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

/// stage2: runs as sysscope-box in the transient unit.
fn stage2(run: &Path, sample_name: &str, args: &[String]) -> Result<()> {
    // Wait until the helper has registered our cgroup for tracing.
    let mut go = std::fs::File::open(run.join("go")).context("opening the go FIFO")?;
    let mut b = [0u8; 1];
    std::io::Read::read(&mut go, &mut b)?;
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.args(bwrap_args(run, sample_name));
    // systemd starts us with only fds 0-2; the seccomp files are the only
    // descriptors we pass on (CLOEXEC cleared on exactly those).
    let mut keep = Vec::new();
    for i in 0..3 {
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
        "LimitCORE=0",
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
    let out = Command::new("setpriv")
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

/// run-local: the root side of one run, without the daemon.
fn run_local(sample: &Path, args: &[String], timeout_s: u32) -> Result<i32> {
    if let Err(why) = availability() {
        eprintln!("Glasshouse unavailable: {why}");
        return Ok(4);
    }
    let id = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    let run = PathBuf::from(RUNS).join(&id);
    std::fs::create_dir_all(&run)?;
    let st = Command::new("mount")
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
        bail!("mounting the run tmpfs failed");
    }
    let result = (|| -> Result<i32> {
        prepare(&run)?;
        let name = sample
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "sample".into());
        std::fs::copy(sample, run.join("sample"))?;
        std::fs::set_permissions(run.join("sample"), std::fs::Permissions::from_mode(0o755))?;
        let fifo = run.join("go");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )?;
        let (box_uid, box_gid) = uid_gid_of(BOX_USER)?;
        rustix::fs::chown(
            &fifo,
            Some(rustix::fs::Uid::from_raw(box_uid)),
            Some(rustix::fs::Gid::from_raw(box_gid)),
        )?;
        let unit = format!("sysscope-gh-{id}");
        let exe = std::env::current_exe()?;
        let mut cmd = Command::new("systemd-run");
        cmd.args(["--wait", "--quiet", "--unit", &unit, "--service-type=exec"]);
        for p in unit_properties(&run, timeout_s) {
            cmd.args(["-p", &p]);
        }
        cmd.arg(&exe).arg("stage2").arg(&run).arg(&name).args(args);
        let mut child = cmd.spawn().context("systemd-run")?;
        // Find the unit's cgroup and report its id (inode of the cgroup dir).
        let cg = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}.service"));
        let mut cg_ino = None;
        for _ in 0..100 {
            if let Ok(m) = std::fs::metadata(&cg) {
                cg_ino = Some(m.ino());
                break;
            }
            if let Ok(Some(st)) = child.try_wait() {
                bail!(
                    "the unit exited before starting (systemd-run status {st}); a required property may be unsupported"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let cg_ino = cg_ino.context("the unit's cgroup did not appear")?;
        eprintln!(
            "glasshouse: unit {unit} cgroup {} id {cg_ino}",
            cg.display()
        );
        // Here the daemon would add cg_ino to followed_cgroup (WP24).
        std::fs::OpenOptions::new()
            .write(true)
            .open(&fifo)?
            .write_all(b"g")?;
        let status = child.wait()?;
        let out = std::fs::read(run.join("stdout")).unwrap_or_default();
        let err = std::fs::read(run.join("stderr")).unwrap_or_default();
        // Sample output is untrusted: printed escaped (I10).
        println!("--- sample stdout ---\n{}", escape_lines(&out));
        println!("--- sample stderr ---\n{}", escape_lines(&err));
        Ok(status.code().unwrap_or(-1))
    })();
    let _ = Command::new("umount").arg(&run).status();
    let _ = std::fs::remove_dir(&run);
    result
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
        Some("stage2") => match (args.get(1), args.get(2)) {
            (Some(run), Some(name)) => {
                stage2(Path::new(run), name, args.get(3..).unwrap_or(&[])).map(|()| 0)
            }
            _ => Err(anyhow::anyhow!("stage2 RUN_DIR SAMPLE_NAME [ARGS]")),
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
        Some("run-local") => match args.get(1) {
            Some(sample) => run_local(Path::new(sample), args.get(2..).unwrap_or(&[]), 60),
            None => Err(anyhow::anyhow!("run-local SAMPLE [ARGS]")),
        },
        _ => Err(anyhow::anyhow!(
            "usage: sysscope-glasshouse prepare RUN_DIR | stage2 RUN_DIR NAME [ARGS] | run-local SAMPLE [ARGS]"
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
