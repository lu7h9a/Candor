//! WP07 network events: exact counts, addresses and ports (plan WP07 Verify).
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use candor_itest::{action, run_wl};
use candor_proto::{Event, EventKind, Family, SockType};

fn connects(ev: &[Event], fam: Family, addr: &str, port: u16, sock: SockType) -> usize {
    ev.iter()
        .filter(|e| {
            matches!(&e.kind, EventKind::Connect { family, addr: a, port: p, sock: s }
                if *family == fam && a == addr && *p == port && *s == sock)
        })
        .count()
}

#[test]
fn connects_and_listens_are_exact() {
    let (m, ev) = run_wl(&[
        "connect-tcp",
        "300",
        "connect-tcp6",
        "300",
        "connect-fail",
        "50",
        "listen",
        "10",
        "connect-udp",
        "1",
    ])
    .unwrap();
    let port = |name: &str| action(&m, name)["port"].as_u64().unwrap() as u16;

    assert_eq!(
        connects(
            &ev,
            Family::Inet,
            "127.0.0.1",
            port("connect-tcp"),
            SockType::Stream
        ),
        300
    );
    assert_eq!(
        connects(
            &ev,
            Family::Inet6,
            "::1",
            port("connect-tcp6"),
            SockType::Stream
        ),
        300
    );
    assert_eq!(action(&m, "connect-fail")["failed"], 50);
    assert_eq!(
        connects(
            &ev,
            Family::Inet,
            "127.0.0.1",
            port("connect-fail"),
            SockType::Stream
        ),
        50
    );
    assert_eq!(
        connects(
            &ev,
            Family::Inet,
            "127.0.0.1",
            port("connect-udp"),
            SockType::Dgram
        ),
        1
    );
    let total = ev
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Connect { .. }))
        .count();
    assert_eq!(total, 651, "no other connects from wl");

    // Each listen port exactly once; plus wl's own listeners for tcp, tcp6, fail.
    let listens: Vec<(String, u16)> = ev
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::Listen { addr, port } => Some((addr.clone(), *port)),
            _ => None,
        })
        .collect();
    for p in action(&m, "listen")["ports"].as_array().unwrap() {
        let p = p.as_u64().unwrap() as u16;
        assert_eq!(
            listens
                .iter()
                .filter(|l| **l == ("127.0.0.1".to_string(), p))
                .count(),
            1,
            "port {p}"
        );
    }
    assert!(listens.contains(&("::1".to_string(), port("connect-tcp6"))));
    assert_eq!(listens.len(), 13);
}
