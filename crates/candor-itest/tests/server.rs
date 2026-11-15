//! WP12 daemon assembly: client limits, slow clients, bad frames, network
//! use, Detail/Follow over the socket, clean shutdown (plan WP12 Verify).
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use candor_itest::{Client, DEV_SOCKET, Daemon, PausedWl, wl, wl_key};
use candor_proto::{ClientMsg, DaemonMsg, EventSub, EventSubMode, ProcKey};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn subscribe(c: &mut Client, events: EventSub) {
    c.send(&ClientMsg::Subscribe {
        snapshots: true,
        alerts: true,
        events,
    })
    .unwrap();
}

#[test]
fn eight_clients_then_the_ninth_is_refused() {
    let d = Daemon::start(&[]).unwrap();
    let mut clients = Vec::new();
    for _ in 0..8 {
        let (c, w) = Client::hello().unwrap();
        assert!(matches!(w, DaemonMsg::Welcome { proto: 1, .. }), "{w:?}");
        clients.push(c);
    }
    let mut ninth = Client::connect().unwrap();
    match ninth.recv().unwrap() {
        DaemonMsg::Error { code, .. } => assert_eq!(code, "too_many_clients"),
        other => panic!("{other:?}"),
    }
    // After one leaves, a new client gets in.
    drop(clients.pop());
    std::thread::sleep(Duration::from_millis(500));
    assert!(matches!(
        Client::hello().unwrap().1,
        DaemonMsg::Welcome { .. }
    ));
    assert!(d.stop().unwrap().success());
}

#[test]
fn slow_client_is_cut_off_and_others_keep_their_snapshots() {
    let d = Daemon::start(&[]).unwrap();
    // The slow client asks for every event and never reads.
    let (mut slow, _) = Client::hello().unwrap();
    subscribe(&mut slow, EventSub::Simple(EventSubMode::All));
    let (mut good, _) = Client::hello().unwrap();
    subscribe(&mut good, EventSub::Simple(EventSubMode::None));
    let load = std::thread::spawn(|| {
        for _ in 0..4 {
            let _ = wl(&["open-read", "50000"]);
        }
    });
    let started = Instant::now();
    let mut last = None;
    let mut max_gap = Duration::ZERO;
    while started.elapsed() < Duration::from_secs(10) {
        if let DaemonMsg::Snapshot { .. } = good.recv().unwrap() {
            let now = Instant::now();
            if let Some(prev) = last {
                max_gap = max_gap.max(now - prev);
            }
            last = Some(now);
        }
    }
    load.join().unwrap();
    assert!(
        max_gap < Duration::from_millis(700),
        "snapshot gap {max_gap:?}"
    );
    // The slow client was disconnected: draining its socket reaches EOF.
    slow.stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut eof = false;
    for _ in 0..10_000 {
        match slow.stream.read(&mut buf) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    assert!(eof, "slow client still connected after 10 s");
    assert!(d.stop().unwrap().success());
}

#[test]
fn bad_frames_get_an_error_and_the_daemon_survives() {
    let d = Daemon::start(&[]).unwrap();
    // Garbage body.
    let mut c = Client::connect().unwrap();
    c.stream.write_all(&5u32.to_le_bytes()).unwrap();
    c.stream.write_all(b"\xff\x00{[x").unwrap();
    match c.recv().unwrap() {
        DaemonMsg::Error { code, .. } => assert_eq!(code, "malformed"),
        other => panic!("{other:?}"),
    }
    assert_eq!(c.recv().unwrap_err(), "eof");
    // Oversized frame (2 MiB > 1 MiB limit).
    let mut c = Client::connect().unwrap();
    c.stream.write_all(&(2u32 << 20).to_le_bytes()).unwrap();
    match c.recv().unwrap() {
        DaemonMsg::Error { code, .. } => assert_eq!(code, "bad_frame"),
        other => panic!("{other:?}"),
    }
    // Unknown type and wrong protocol version.
    let mut c = Client::connect().unwrap();
    c.stream.write_all(&12u32.to_le_bytes()).unwrap();
    c.stream.write_all(br#"{"t":"Nope"}"#).unwrap();
    assert!(matches!(c.recv().unwrap(), DaemonMsg::Error { code, .. } if code == "unknown_type"));
    let mut c = Client::connect().unwrap();
    c.send(&ClientMsg::Hello {
        proto: 99,
        client: candor_proto::ClientKind::Cli,
        version: "x".into(),
    })
    .unwrap();
    assert!(matches!(c.recv().unwrap(), DaemonMsg::Error { code, .. } if code == "proto_mismatch"));
    // Still alive and serving.
    assert!(matches!(
        Client::hello().unwrap().1,
        DaemonMsg::Welcome { .. }
    ));
    assert!(d.stop().unwrap().success());
}

#[test]
fn detail_and_follow_work_over_the_socket() {
    let d = Daemon::start(&[]).unwrap();
    let w = PausedWl::start(&["sleep", "4000"]).unwrap();
    let pid = w.pid();
    let (mut c, _) = Client::hello().unwrap();
    subscribe(&mut c, EventSub::Simple(EventSubMode::None));
    // Wait until the sampler has seen the paused wl, then use its key.
    let key: ProcKey = loop {
        if let DaemonMsg::Snapshot { procs, .. } = c.recv().unwrap()
            && let Some(r) = procs.iter().find(|r| r.key.tgid == pid)
            && r.n_exec > 0
        {
            // An ordinary process is not marked as a private view (Q7 A),
            // and neither is the daemon, even inside its hardened unit's
            // own mount namespace (same files as the host).
            assert!(!r.private_view, "{r:?}");
            if let Some(dr) = procs.iter().find(|r| r.key.tgid == d.pid()) {
                assert!(!dr.private_view, "{dr:?}");
            }
            break r.key;
        }
    };
    c.send(&ClientMsg::GetDetail {
        proc: key,
        maps: true,
    })
    .unwrap();
    match c
        .recv_until(|m| matches!(m, DaemonMsg::Detail { .. } | DaemonMsg::Error { .. }))
        .unwrap()
    {
        DaemonMsg::Detail { proc, maps, .. } => {
            assert_eq!(proc, key);
            assert!(!maps.unwrap().is_empty());
        }
        other => panic!("{other:?}"),
    }
    c.send(&ClientMsg::Follow { root: key }).unwrap();
    match c
        .recv_until(|m| matches!(m, DaemonMsg::ActResult { .. } | DaemonMsg::Error { .. }))
        .unwrap()
    {
        DaemonMsg::ActResult { ok, message } => {
            assert!(ok && message.contains("following"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    let mode = c
        .recv_until(|m| {
            matches!(
                m,
                DaemonMsg::Snapshot {
                    mode: candor_proto::Mode::Follow { .. },
                    ..
                }
            )
        })
        .unwrap();
    if let DaemonMsg::Snapshot { procs, .. } = mode {
        assert!(procs.iter().any(|r| r.key == key && r.followed));
    }
    // Follow limits detection for everyone, so it is logged (review F9).
    let want = format!("follow pid {} requested by uid 0", key.tgid);
    assert!(d.stderr_text().contains(&want), "{}", d.stderr_text());
    let m = w.release().unwrap();
    assert_eq!(wl_key(&m), key);
    assert!(d.stop().unwrap().success());
}

#[test]
fn sigterm_removes_the_socket() {
    let d = Daemon::start(&[]).unwrap();
    assert!(std::path::Path::new(DEV_SOCKET).exists());
    assert!(d.stop().unwrap().success());
    assert!(!std::path::Path::new(DEV_SOCKET).exists());
}

#[test]
fn daemon_uses_only_unix_and_netlink_sockets() {
    let log = std::env::temp_dir().join("candor-strace.log");
    let log_s = log.to_string_lossy().into_owned();
    // strace runs the daemon from the start (attaching later may be refused).
    let d =
        Daemon::start_under(&["strace", "-f", "-e", "trace=network", "-o", &log_s], &[]).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        let (mut c, _) = Client::hello().unwrap();
        subscribe(&mut c, EventSub::Simple(EventSubMode::All));
        let _ = wl(&["connect-tcp", "20", "connect-tcp6", "20"]);
        let _ = c.recv();
    }
    assert!(d.stop().unwrap().success());
    let text = std::fs::read_to_string(&log).unwrap();
    let families: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split("AF_").nth(1))
        .map(|rest| {
            rest.split(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .unwrap_or("")
        })
        .collect();
    assert!(
        !families.is_empty(),
        "strace saw no socket calls:\n{}",
        &text[..text.len().min(2000)]
    );
    let bad: Vec<_> = families
        .iter()
        .filter(|f| !matches!(**f, "UNIX" | "LOCAL" | "NETLINK"))
        .collect();
    assert!(bad.is_empty(), "daemon used other families: {bad:?}");
}

fn key_of(c: &mut Client, pid: u32) -> ProcKey {
    loop {
        if let DaemonMsg::Snapshot { procs, .. } = c.recv().unwrap()
            && let Some(r) = procs.iter().find(|r| r.key.tgid == pid)
        {
            return r.key;
        }
    }
}

/// Review findings 3/4: following a second tree stops tracing the first; a
/// stale key is refused and tracing stays system-wide.
#[test]
fn follow_switch_and_stale_key() {
    let d = Daemon::start(&[]).unwrap();
    let a = PausedWl::start(&["sleep", "6000", "open-read", "50"]).unwrap();
    let b = PausedWl::start(&["sleep", "6000", "open-read", "50"]).unwrap();
    let (mut c, _) = Client::hello().unwrap();
    subscribe(&mut c, EventSub::Simple(EventSubMode::All));
    let ka = key_of(&mut c, a.pid());
    let kb = key_of(&mut c, b.pid());
    // Stale key: right pid, wrong start time.
    c.send(&ClientMsg::Follow {
        root: ProcKey {
            tgid: ka.tgid,
            start_ticks: ka.start_ticks + 1,
        },
    })
    .unwrap();
    let m = c
        .recv_until(|m| matches!(m, DaemonMsg::Error { .. } | DaemonMsg::ActResult { .. }))
        .unwrap();
    assert!(matches!(m, DaemonMsg::Error { .. }), "{m:?}");
    let s = c
        .recv_until(|m| matches!(m, DaemonMsg::Snapshot { .. }))
        .unwrap();
    assert!(matches!(
        s,
        DaemonMsg::Snapshot {
            mode: candor_proto::Mode::System(_),
            ..
        }
    ));
    // Follow A, then switch to B.
    c.send(&ClientMsg::Follow { root: ka }).unwrap();
    c.recv_until(|m| matches!(m, DaemonMsg::ActResult { ok: true, .. }))
        .unwrap();
    c.send(&ClientMsg::Follow { root: kb }).unwrap();
    c.recv_until(|m| matches!(m, DaemonMsg::ActResult { ok: true, .. }))
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    let (ma, mb) = (
        std::thread::spawn(move || a.release().unwrap()),
        std::thread::spawn(move || b.release().unwrap()),
    );
    let (_ma, _mb) = (ma.join().unwrap(), mb.join().unwrap());
    let mut from_a = 0;
    let mut from_b = 0;
    while started.elapsed() < Duration::from_secs(9) {
        if let Ok(DaemonMsg::Events { events, .. }) = c.recv() {
            from_a += events.iter().filter(|e| e.proc == ka).count();
            from_b += events.iter().filter(|e| e.proc == kb).count();
        }
    }
    assert_eq!(from_a, 0, "old followed tree still traced");
    assert!(from_b >= 50, "new followed tree: {from_b} events");
    assert!(d.stop().unwrap().success());
}

/// Follows a paused wl that will make `n` getppid calls; returns its
/// getppid count from Detail after it ran (owner's Q5 B: in follow mode
/// syscall hooks run only while some client sends WatchSyscalls on).
fn followed_getppid_count(watch: bool, n: &str) -> u64 {
    let w = PausedWl::start(&["syscalls", "getppid", n]).unwrap();
    let pid = w.pid();
    let (mut c, _) = Client::hello().unwrap();
    subscribe(&mut c, EventSub::Simple(EventSubMode::None));
    let key: ProcKey = loop {
        if let DaemonMsg::Snapshot { procs, .. } = c.recv().unwrap()
            && let Some(r) = procs.iter().find(|r| r.key.tgid == pid)
        {
            break r.key;
        }
    };
    c.send(&ClientMsg::Follow { root: key }).unwrap();
    c.recv_until(|m| matches!(m, DaemonMsg::ActResult { .. }))
        .unwrap();
    c.send(&ClientMsg::WatchSyscalls { on: watch }).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    w.release().unwrap();
    // Syscall totals are read every 5 s.
    std::thread::sleep(Duration::from_secs(7));
    c.send(&ClientMsg::GetDetail {
        proc: key,
        maps: false,
    })
    .unwrap();
    let n = match c
        .recv_until(|m| matches!(m, DaemonMsg::Detail { .. }))
        .unwrap()
    {
        DaemonMsg::Detail { syscalls, .. } => syscalls
            .iter()
            .find(|s| s.name == "getppid")
            .map(|s| s.count)
            .unwrap_or(0),
        _ => unreachable!(),
    };
    c.send(&ClientMsg::Unfollow {}).unwrap();
    c.recv_until(|m| matches!(m, DaemonMsg::ActResult { .. }))
        .unwrap();
    n
}

#[test]
fn follow_mode_counts_syscalls_only_while_someone_watches() {
    let d = Daemon::start(&[]).unwrap();
    assert_eq!(
        followed_getppid_count(false, "20000"),
        0,
        "hooks ran without a viewer"
    );
    assert!(
        followed_getppid_count(true, "20000") >= 20000,
        "not counted while watched"
    );
    assert!(d.stop().unwrap().success());
}

/// Connections that never say Hello are closed after HELLO_TIMEOUT (10 s),
/// so eight silent sockets cannot lock every real client out (review F11).
#[test]
fn silent_connections_do_not_hold_client_slots() {
    let d = Daemon::start(&[]).unwrap();
    let mut silent: Vec<Client> = (0..8).map(|_| Client::connect().unwrap()).collect();
    for s in &silent {
        // Longer than the daemon's 10 s, so the daemon closes first.
        s.stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
    }
    // While they are open, a real client is refused.
    let mut early = Client::connect().unwrap();
    assert!(
        matches!(early.recv().unwrap(), DaemonMsg::Error { code, .. } if code == "too_many_clients")
    );
    for s in &mut silent {
        match s.recv().unwrap() {
            DaemonMsg::Error { code, .. } => assert_eq!(code, "no_hello"),
            other => panic!("{other:?}"),
        }
    }
    drop(silent);
    std::thread::sleep(Duration::from_millis(300));
    let (_c, w) = Client::hello().unwrap();
    assert!(matches!(w, DaemonMsg::Welcome { .. }), "{w:?}");
    assert!(d.stop().unwrap().success());
}

/// A non-root client gets memory maps only of its own processes, as the
/// kernel's /proc/<pid>/maps rule (review 2 finding 2).
#[test]
fn maps_only_of_the_requesters_own_processes() {
    let d = Daemon::start(&[]).unwrap();
    let dir = std::env::temp_dir().join(format!("candor-maps-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::os::unix::fs::chown(&dir, Some(65534), Some(65534)).unwrap();
    let mut mine = std::process::Command::new("setpriv")
        .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
        .arg(candor_itest::bin_dir().join("candor-wl"))
        .arg("--dir")
        .arg(&dir)
        .args(["sleep", "300000"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    let sock = std::os::unix::fs::MetadataExt::gid(&std::fs::metadata("/run/candor-dev").unwrap());
    let maps_of = |pid: u32| -> serde_json::Value {
        let o = std::process::Command::new("setpriv")
            .args(["--reuid=65534", "--regid=65534"])
            .arg(format!("--groups={sock}"))
            .arg(candor_itest::bin_dir().join("candor"))
            .args(["--json", "detail", &pid.to_string(), "--maps"])
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        v["maps"].clone()
    };
    assert!(
        maps_of(d.pid()).is_null(),
        "root process maps given to nobody"
    );
    let own = maps_of(mine.id());
    assert!(own.as_array().is_some_and(|m| !m.is_empty()), "{own}");
    mine.kill().unwrap();
    mine.wait().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(d.stop().unwrap().success());
}

/// One non-root user holds at most 4 of the 8 client slots (review 2
/// finding 7); the fifth connection of that user is refused.
#[test]
fn one_user_cannot_take_every_client_slot() {
    let d = Daemon::start(&[]).unwrap();
    let sock = std::os::unix::fs::MetadataExt::gid(&std::fs::metadata("/run/candor-dev").unwrap());
    // As nobody: open five connections, read the first reply of the fifth.
    let py = r#"
import socket, struct, json, time
socks = []
for i in range(5):
    s = socket.socket(socket.AF_UNIX); s.connect("/run/candor-dev/candor.sock"); socks.append(s)
    time.sleep(0.1)
s = socks[4]; s.settimeout(5)
n = struct.unpack("<I", s.recv(4))[0]; body = b""
while len(body) < n: body += s.recv(n - len(body))
print(json.loads(body)["code"])
"#;
    let o = std::process::Command::new("setpriv")
        .args(["--reuid=65534", "--regid=65534"])
        .arg(format!("--groups={sock}"))
        .args(["python3", "-c", py])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "too_many_clients"
    );
    assert!(
        d.stderr_text().contains("already connected for that user"),
        "{}",
        d.stderr_text()
    );
    // Root is not limited and still gets in.
    assert!(matches!(
        Client::hello().unwrap().1,
        DaemonMsg::Welcome { .. }
    ));
    assert!(d.stop().unwrap().success());
}
