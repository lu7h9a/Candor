//! WP27 act mode (experimental, D19): every refusal reason, the pid-reuse
//! refusal, and pause/resume/kill of a workload child (plan WP27 Verify).
//! Needs root and the group sysscope-act (packaging/sysusers). The pid-reuse
//! test forces /proc/sys/kernel/ns_last_pid and runs only in a test VM.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;
use sysscope_itest::{Client, Daemon, bin_dir};
use sysscope_proto::{ActAction, ClientMsg, DaemonMsg, ProcKey};

const NOBODY: u32 = 65534;

fn stat_fields(pid: u32) -> Vec<String> {
    let t = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let close = t.rfind(')').unwrap();
    t[close + 2..]
        .split_whitespace()
        .map(String::from)
        .collect()
}

fn state(pid: u32) -> char {
    stat_fields(pid)[0].chars().next().unwrap()
}

fn start_ticks(pid: u32) -> u64 {
    stat_fields(pid)[19].parse().unwrap()
}

fn act_gid() -> u32 {
    std::fs::read_to_string("/etc/group")
        .unwrap()
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f[0] == "sysscope-act").then(|| f[2].parse().unwrap())
        })
        .expect("group sysscope-act missing: install packaging/sysusers/sysscope.conf")
}

/// The CLI, as root or as `nobody` with the given supplementary groups.
fn cli(as_nobody: Option<&[u32]>, args: &[&str]) -> Output {
    let mut c = match as_nobody {
        None => Command::new(bin_dir().join("sysscope")),
        Some(groups) => {
            let g: Vec<String> = groups.iter().map(u32::to_string).collect();
            let mut c = Command::new("setpriv");
            c.arg(format!("--reuid={NOBODY}"))
                .arg(format!("--regid={NOBODY}"))
                .arg(format!("--groups={}", g.join(",")))
                .arg(bin_dir().join("sysscope"));
            c
        }
    };
    c.args(args).output().unwrap()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A long-sleeping workload child (optionally as nobody).
fn sleeper(as_nobody: bool) -> Child {
    let dir = std::env::temp_dir().join(format!("sysscope-act-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut c = if as_nobody {
        let mut c = Command::new("setpriv");
        c.arg(format!("--reuid={NOBODY}"))
            .arg(format!("--regid={NOBODY}"))
            .arg("--clear-groups")
            .arg(bin_dir().join("sysscope-wl"));
        c
    } else {
        Command::new(bin_dir().join("sysscope-wl"))
    };
    c.arg("--dir")
        .arg(&dir)
        .args(["sleep", "300000"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn settle() {
    std::thread::sleep(Duration::from_millis(1500)); // the daemon's next snapshot
}

#[test]
fn act_is_refused_unless_enabled() {
    let d = Daemon::start(&[]).unwrap();
    let mut s = sleeper(false);
    settle();
    let o = cli(None, &["act", "pause", &s.id().to_string()]);
    assert!(!o.status.success());
    assert!(err(&o).contains("act mode is not enabled"), "{}", err(&o));
    assert_ne!(state(s.id()), 'T');
    s.kill().unwrap();
    s.wait().unwrap();
    assert!(d.stop().unwrap().success());
}

#[test]
fn pause_resume_and_kill_a_workload_child() {
    let d = Daemon::start(&["--enable-act"]).unwrap();
    let mut s = sleeper(false);
    settle();
    let pid = s.id().to_string();
    let o = cli(None, &["act", "pause", &pid]);
    assert!(o.status.success(), "{}", err(&o));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(state(s.id()), 'T');
    let o = cli(None, &["act", "resume", &pid]);
    assert!(o.status.success(), "{}", err(&o));
    std::thread::sleep(Duration::from_millis(200));
    assert_ne!(state(s.id()), 'T');
    let o = cli(None, &["act", "kill", &pid]);
    assert!(o.status.success(), "{}", err(&o));
    let st = s.wait().unwrap();
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&st), Some(9));
    // Every action is logged with the requester.
    let log = d.stderr_text();
    assert!(
        log.contains(&format!("act Pause pid {pid} requested by uid 0")),
        "{log}"
    );
    assert!(
        log.contains(&format!("act Kill pid {pid} requested by uid 0")),
        "{log}"
    );
    assert!(d.stop().unwrap().success());
}

#[test]
fn protected_processes_are_refused() {
    let d = Daemon::start(&["--enable-act"]).unwrap();
    // A process named like a display server, in the requester's session.
    let dir = std::env::temp_dir().join(format!("sysscope-act-x-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy("/usr/bin/sleep", dir.join("Xorg")).unwrap();
    let mut x = Command::new(dir.join("Xorg")).arg("300").spawn().unwrap();
    settle();
    let me = std::process::id();
    let cases: [(u32, &str); 5] = [
        (1, "pid 1"),
        (2, "kernel threads"),
        (d.pid(), "daemon itself"),
        (me, "ancestor of the client"),
        (x.id(), "display server"),
    ];
    for (pid, why) in cases {
        let o = cli(None, &["act", "kill", &pid.to_string()]);
        assert!(!o.status.success(), "pid {pid} was not refused");
        assert!(err(&o).contains(why), "pid {pid}: {}", err(&o));
    }
    assert_ne!(state(x.id()), 'Z');
    x.kill().unwrap();
    x.wait().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(d.stop().unwrap().success());
}

#[test]
fn non_root_needs_the_group_and_ownership() {
    let gid = act_gid();
    let d = Daemon::start(&["--enable-act"]).unwrap();
    let mut mine = sleeper(true); // owned by nobody
    let mut roots = sleeper(false); // owned by root
    settle();
    // The dev socket's group (SUDO_GID under sudo, else root) lets nobody
    // connect; without sysscope-act it is not authorised to act.
    let sock =
        std::os::unix::fs::MetadataExt::gid(&std::fs::metadata("/run/sysscope-dev").unwrap());
    let o = cli(Some(&[sock]), &["act", "pause", &mine.id().to_string()]);
    assert!(err(&o).contains("not authorised"), "{}", err(&o));
    assert_ne!(state(mine.id()), 'T');
    // With the group: someone else's process is still refused...
    let o = cli(
        Some(&[sock, gid]),
        &["act", "pause", &roots.id().to_string()],
    );
    assert!(
        err(&o).contains("could not signal that process yourself"),
        "{}",
        err(&o)
    );
    assert_ne!(state(roots.id()), 'T');
    // ...and its own process works.
    let o = cli(
        Some(&[sock, gid]),
        &["act", "pause", &mine.id().to_string()],
    );
    assert!(o.status.success(), "{}", err(&o));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(state(mine.id()), 'T');
    assert!(
        d.stderr_text()
            .contains(&format!("requested by uid {NOBODY}"))
    );
    for c in [&mut mine, &mut roots] {
        c.kill().unwrap();
        c.wait().unwrap();
    }
    assert!(d.stop().unwrap().success());
}

#[test]
fn a_recycled_pid_is_refused() {
    if !std::path::Path::new("/etc/sysscope-test-vm").exists() {
        eprintln!("skipped: forcing ns_last_pid is done only inside a test VM");
        return;
    }
    let d = Daemon::start(&["--enable-act"]).unwrap();
    let (_, _) = Client::hello().unwrap();
    // Process A: remember its key, then let it exit.
    let mut a = sleeper(false);
    let old = ProcKey {
        tgid: a.id(),
        start_ticks: start_ticks(a.id()),
    };
    a.kill().unwrap();
    a.wait().unwrap();
    // Make the next pid equal to A's (more than one clock tick later).
    let mut b = None;
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(50));
        std::fs::write("/proc/sys/kernel/ns_last_pid", (old.tgid - 1).to_string()).unwrap();
        let c = sleeper(false);
        if c.id() == old.tgid {
            b = Some(c);
            break;
        }
        let mut c = c;
        c.kill().unwrap();
        c.wait().unwrap();
    }
    let mut b = b.expect("could not recycle the pid");
    assert_ne!(start_ticks(b.id()), old.start_ticks);
    let (mut c, _) = Client::hello().unwrap();
    c.send(&ClientMsg::Act {
        proc: old,
        action: ActAction::Kill,
        nonce: "reuse".into(),
    })
    .unwrap();
    let reply = loop {
        match c.recv().unwrap() {
            DaemonMsg::ActResult { ok, message } => break (ok, message),
            _ => continue,
        }
    };
    assert!(!reply.0, "{}", reply.1);
    assert!(
        reply.1.contains("now belongs to another process"),
        "{}",
        reply.1
    );
    assert_ne!(state(b.id()), 'Z');
    b.kill().unwrap();
    b.wait().unwrap();
    assert!(d.stop().unwrap().success());
}
