//! WP12 daemon assembly: client limits, slow clients, bad frames, network
//! use, Detail/Follow over the socket, clean shutdown (plan WP12 Verify).
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::time::{Duration, Instant};
use sysscope_itest::{Client, DEV_SOCKET, Daemon, PausedWl, wl, wl_key};
use sysscope_proto::{ClientMsg, DaemonMsg, EventSub, EventSubMode, ProcKey};

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
        client: sysscope_proto::ClientKind::Cli,
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
        {
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
                    mode: sysscope_proto::Mode::Follow { .. },
                    ..
                }
            )
        })
        .unwrap();
    if let DaemonMsg::Snapshot { procs, .. } = mode {
        assert!(procs.iter().any(|r| r.key == key && r.followed));
    }
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
    let log = std::env::temp_dir().join("sysscope-strace.log");
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
