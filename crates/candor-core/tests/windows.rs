//! WP17 caps: windowed-rule state is bounded (I8).
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use candor_core::limits::{BEACON_POINTS, WINDOW_ENTRIES};
use candor_core::{Engine, Input};
use candor_proto::{BStr, Event, EventKind, Family, ProcKey, SockType};

fn ev(id: u64, ts: u64, kind: EventKind) -> Input {
    Input::RawEvent {
        event: Event {
            id,
            ts_ns: ts,
            proc: ProcKey {
                tgid: 9,
                start_ticks: 1,
            },
            tid: 9,
            uid: 1000,
            kind,
        },
    }
}

#[test]
fn beacon_destinations_are_capped_at_max_keys() {
    let mut e = Engine::with_defaults().unwrap();
    let max = e.detector.rules().rule("R006").unwrap().max_keys.unwrap();
    for i in 0..(max as u64 + 1000) {
        let kind = EventKind::Connect {
            family: Family::Inet,
            addr: format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
            port: 443,
            sock: SockType::Stream,
        };
        e.apply(&ev(i, i, kind));
    }
    assert_eq!(e.windows().beacon_keys(), max);
}

#[test]
fn rule_windows_are_capped() {
    let mut e = Engine::with_defaults().unwrap();
    let k = ProcKey {
        tgid: 9,
        start_ticks: 1,
    };
    // All within one 10 s window: only the cap can limit the windows.
    for i in 0..(WINDOW_ENTRIES as u64 + 1000) {
        let open = EventKind::Open {
            path: BStr::from(format!("/home/u/f{i}").as_str()),
            dev: 1,
            ino: i,
            read: false,
            write: true,
            create: true,
            trunc: false,
            path_trunc: false,
        };
        e.apply(&ev(2 * i, i, open));
        let conn = EventKind::Connect {
            family: Family::Inet,
            addr: "10.0.0.1".into(),
            port: 443,
            sock: SockType::Stream,
        };
        e.apply(&ev(2 * i + 1, i, conn));
    }
    assert_eq!(
        e.windows().window_lens(&k),
        (WINDOW_ENTRIES, WINDOW_ENTRIES)
    );
}

/// Review finding 7: alert state is pruned with the process table.
#[test]
fn alert_state_is_pruned_with_evicted_processes() {
    let mut e = Engine::with_defaults().unwrap();
    for i in 0..3000u32 {
        let k = ProcKey {
            tgid: 10_000 + i,
            start_ticks: 1,
        };
        let exec = EventKind::Exec {
            exe: BStr::from("/tmp/x"),
            argv: BStr::from("x"),
            argv_trunc: false,
            fileless: false,
            dev: 1,
            ino: 1,
        };
        e.apply(&Input::RawEvent {
            event: Event {
                id: u64::from(i),
                ts_ns: u64::from(i),
                proc: k,
                tid: k.tgid,
                uid: 1000,
                kind: exec,
            },
        });
        e.apply(&Input::RawEvent {
            event: Event {
                id: 100_000 + u64::from(i),
                ts_ns: u64::from(i),
                proc: k,
                tid: k.tgid,
                uid: 1000,
                kind: EventKind::Exit {},
            },
        });
    }
    e.apply(&Input::Tick { ts_ns: 4000 });
    // Exited processes beyond MAX_EXITED_PROCS were evicted; so was their alert state.
    assert!(e.detector.alerted_len() <= candor_core::limits::MAX_EXITED_PROCS);
    assert!(e.detector.alerted_len() > 0);
}

#[test]
fn beacon_points_per_destination_are_capped() {
    let mut e = Engine::with_defaults().unwrap();
    for i in 0..(BEACON_POINTS as u64 + 1000) {
        let kind = EventKind::Connect {
            family: Family::Inet,
            addr: "10.1.2.3".into(),
            port: 443,
            sock: SockType::Stream,
        };
        e.apply(&ev(i, i * 1_000_000_000, kind));
    }
    assert_eq!(e.windows().beacon_keys(), 1);
    assert_eq!(e.windows().beacon_points_max(), BEACON_POINTS);
}
