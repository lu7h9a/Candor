//! WP11 tests: every retention cap, tree invariants, sampling and replay.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use candor_core::limits::*;
use candor_core::{Input, ProcSample, State};
use candor_proto::{BStr, DaemonMsg, Event, EventKind, Family, ProcKey, SockType, SysStat};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};

const SEC: u64 = 1_000_000_000;

fn key(tgid: u32) -> ProcKey {
    ProcKey {
        tgid,
        start_ticks: u64::from(tgid) * 7,
    }
}

fn ev(id: u64, ts: u64, proc: ProcKey, kind: EventKind) -> Event {
    Event {
        id,
        ts_ns: ts,
        proc,
        tid: proc.tgid,
        uid: 1000,
        kind,
    }
}

fn open(path: &str, ino: u64) -> EventKind {
    EventKind::Open {
        path: BStr::from(path),
        dev: 1,
        ino,
        read: true,
        write: false,
        create: false,
        trunc: false,
        path_trunc: false,
    }
}

fn sample(k: ProcKey, ppid: u32, cpu_ticks: u64) -> ProcSample {
    ProcSample {
        key: k,
        ppid,
        exe: BStr::from("/usr/bin/x"),
        comm: BStr::from("x"),
        uid: 1000,
        kthread: false,
        cpu_ticks,
        rss: 4096,
        threads: 1,
        io_r: 0,
        io_w: 0,
    }
}

#[test]
fn live_process_cap_holds() {
    let mut s = State::new();
    let root = key(1);
    let n = MAX_LIVE_PROCS as u32 + 1000;
    for i in 0..n {
        s.apply_event(&ev(
            u64::from(i),
            1,
            root,
            EventKind::Fork { child: key(10 + i) },
        ));
    }
    assert_eq!(s.live_count(), MAX_LIVE_PROCS);
    assert_eq!(s.stats().procs_refused, 1001); // root takes one slot
    // An event of a process the table could not hold is counted in the
    // snapshot's loss, so users see it (I3, review 2 finding 4).
    let refused = key(10 + n - 1);
    s.apply_event(&ev(u64::from(n), 2, refused, EventKind::Exit {}));
    let untracked = s.stats().events_unattributed;
    assert!(untracked >= 1, "{untracked}");
    match s.snapshot(1) {
        candor_proto::DaemonMsg::Snapshot { loss, .. } => assert_eq!(loss.untracked, untracked),
        other => panic!("{other:?}"),
    }
}

#[test]
fn exited_cap_and_retention_hold() {
    let mut s = State::new();
    let n = MAX_EXITED_PROCS as u32 + 1000;
    for i in 0..n {
        let k = key(10 + i);
        s.apply_event(&ev(u64::from(i), u64::from(i) + 1, k, EventKind::Exit {}));
    }
    assert_eq!(s.exited_count(), MAX_EXITED_PROCS);
    assert_eq!(s.stats().procs_evicted, 1000);
    // The oldest were evicted first.
    assert!(s.get(&key(10)).is_none());
    assert!(s.get(&key(10 + n - 1)).is_some());
    // Retention: 600 s after the last exit everything has gone.
    s.tick(u64::from(n) + EXITED_RETENTION_NS + 1);
    assert_eq!(s.exited_count(), 0);
}

#[test]
fn exited_process_survives_until_retention() {
    let mut s = State::new();
    s.apply_event(&ev(1, SEC, key(5), EventKind::Exit {}));
    s.tick(SEC + EXITED_RETENTION_NS);
    assert!(s.get(&key(5)).is_some());
    s.tick(SEC + EXITED_RETENTION_NS + 1);
    assert!(s.get(&key(5)).is_none());
}

#[test]
fn per_process_and_global_event_caps_hold() {
    let mut s = State::new();
    let p = key(2);
    let n = GLOBAL_EVENTS as u64 + 1000;
    for i in 0..n {
        s.apply_event(&ev(i, i, p, open("/etc/hosts", 1)));
    }
    assert_eq!(s.global_events().len(), GLOBAL_EVENTS);
    assert_eq!(s.global_events().front().unwrap().id, 1000);
    let pr = s.get(&p).unwrap();
    assert_eq!(pr.recent.len(), PER_PROC_RECENT_EVENTS);
    assert_eq!(pr.n_open, n);
}

#[test]
fn file_and_connection_summaries_are_capped() {
    let mut s = State::new();
    let p = key(3);
    for i in 0..(PER_PROC_FILES as u64 + 1000) {
        s.apply_event(&ev(i, i, p, open("/tmp/f", i)));
    }
    for i in 0..(PER_PROC_CONNS as u64 + 1000) {
        let kind = EventKind::Connect {
            family: Family::Inet,
            addr: format!("10.0.{}.{}", i / 256, i % 256),
            port: 443,
            sock: SockType::Stream,
        };
        s.apply_event(&ev(100_000 + i, i, p, kind));
    }
    let pr = s.get(&p).unwrap();
    assert_eq!(pr.files.len(), PER_PROC_FILES);
    assert_eq!(pr.files_other, 1000);
    assert_eq!(pr.conns.len(), PER_PROC_CONNS);
    assert_eq!(pr.conns_other, 1000);
}

#[test]
fn series_is_capped_and_cpu_percent_is_computed() {
    let mut s = State::new();
    let p = key(4);
    for i in 0..(SERIES_POINTS as u64 + 1000) {
        // 50 ticks per second of CPU = 50 % of one core.
        s.apply_samples(i * SEC, &[sample(p, 0, i * 50)]);
    }
    let pr = s.get(&p).unwrap();
    assert_eq!(pr.series.len(), SERIES_POINTS);
    assert!((pr.cpu_pct - 50.0).abs() < 0.01, "{}", pr.cpu_pct);
}

#[test]
fn missing_from_two_scans_means_exited() {
    let mut s = State::new();
    let (a, b) = (key(20), key(21));
    s.apply_samples(SEC, &[sample(a, 0, 0), sample(b, 20, 0)]);
    assert_eq!(s.get(&b).unwrap().parent, Some(a));
    s.apply_samples(2 * SEC, &[sample(a, 0, 0)]);
    assert!(s.get(&b).unwrap().is_live());
    s.apply_samples(3 * SEC, &[sample(a, 0, 0)]);
    assert_eq!(s.get(&b).unwrap().exited_ts, Some(3 * SEC));
}

#[test]
fn unknown_process_gets_a_placeholder_filled_by_samples() {
    let mut s = State::new();
    let p = key(30);
    s.apply_event(&ev(1, SEC, p, open("/etc/passwd", 9)));
    assert!(s.get(&p).unwrap().placeholder);
    s.apply_samples(2 * SEC, &[sample(p, 0, 0)]);
    let pr = s.get(&p).unwrap();
    assert!(!pr.placeholder);
    assert_eq!(pr.exe, BStr::from("/usr/bin/x"));
}

#[test]
fn exec_replaces_exe_in_place_and_orphans_keep_parent_until_eviction() {
    let mut s = State::new();
    let (parent, child) = (key(40), key(41));
    s.apply_event(&ev(1, SEC, parent, EventKind::Fork { child }));
    s.apply_event(&ev(
        2,
        SEC,
        child,
        EventKind::Exec {
            exe: BStr::from("/usr/bin/new"),
            argv: BStr::from("new"),
            argv_trunc: false,
            fileless: false,
            dev: 1,
            ino: 2,
        },
    ));
    assert_eq!(s.get(&child).unwrap().exe, BStr::from("/usr/bin/new"));
    s.apply_event(&ev(3, 2 * SEC, parent, EventKind::Exit {}));
    // Parent exited but is still kept: the child keeps its parent key.
    assert_eq!(s.get(&child).unwrap().parent, Some(parent));
    s.tick(2 * SEC + EXITED_RETENTION_NS + 1);
    let c = s.get(&child).unwrap();
    assert_eq!(c.parent, None);
    assert!(c.orphan);
}

#[test]
fn cycles_are_refused() {
    let mut s = State::new();
    let (a, b) = (key(50), key(51));
    s.apply_event(&ev(1, 1, a, EventKind::Fork { child: b }));
    s.apply_event(&ev(2, 2, b, EventKind::Fork { child: a }));
    s.apply_event(&ev(3, 3, a, EventKind::Fork { child: a }));
    assert_eq!(s.get(&a).unwrap().parent, None);
    assert!(s.stats().cycles_refused >= 2);
}

#[test]
fn detail_contains_summaries() {
    let mut s = State::new();
    let p = key(60);
    s.apply_event(&ev(1, 1, p, open("/etc/hosts", 7)));
    match s.detail(&p).unwrap() {
        DaemonMsg::Detail { files, recent, .. } => {
            assert_eq!(files.len(), 1);
            assert_eq!(recent.len(), 1);
        }
        other => panic!("{other:?}"),
    }
    assert!(s.detail(&key(999)).is_none());
}

// ---- property test: tree invariants and counters for random sequences ----

fn arb_input() -> impl Strategy<Value = Input> {
    let k = (1u32..40).prop_map(key);
    let kind = prop_oneof![
        (1u32..40).prop_map(|c| EventKind::Fork { child: key(c) }),
        Just(EventKind::Exit {}),
        (0u64..20).prop_map(|i| open("/f", i)),
        (0u16..5).prop_map(|p| EventKind::Connect {
            family: Family::Inet,
            addr: "127.0.0.1".into(),
            port: p,
            sock: SockType::Stream
        }),
    ];
    prop_oneof![
        8 => (k, kind, 0u64..100).prop_map(|(k, kind, t)| Input::RawEvent { event: ev(0, t * SEC, k, kind) }),
        1 => proptest::collection::vec((1u32..40, 0u32..40), 0..10).prop_map(|v| Input::Samples {
            ts_ns: 50 * SEC,
            samples: {
                let mut seen = HashSet::new();
                v.into_iter().filter(|(t, _)| seen.insert(*t)).map(|(t, pp)| sample(key(t), pp, 0)).collect()
            },
        }),
        1 => (0u64..2000).prop_map(|t| Input::Tick { ts_ns: t * SEC }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn tree_and_counters_stay_consistent(inputs in proptest::collection::vec(arb_input(), 0..300)) {
        let mut s = State::new();
        // Naive recount of opens/connects per process, reset on eviction.
        let mut opens: HashMap<ProcKey, u64> = HashMap::new();
        let mut conns: HashMap<ProcKey, u64> = HashMap::new();
        for input in &inputs {
            s.apply(input);
            if let Input::RawEvent { event } = input {
                match event.kind {
                    EventKind::Open { .. } => *opens.entry(event.proc).or_default() += 1,
                    EventKind::Connect { .. } => *conns.entry(event.proc).or_default() += 1,
                    _ => {}
                }
            }
            // Evicted processes restart from zero if they reappear.
            opens.retain(|k, _| s.get(k).is_some());
            conns.retain(|k, _| s.get(k).is_some());
        }
        for p in s.procs() {
            // Parent exists or is null; child is listed under its parent.
            if let Some(parent) = p.parent {
                let pp = s.get(&parent);
                prop_assert!(pp.is_some(), "dangling parent");
                prop_assert!(pp.unwrap().children.contains(&p.key));
            }
            for c in &p.children {
                prop_assert_eq!(s.get(c).and_then(|x| x.parent), Some(p.key));
            }
            // No cycles: walking up ends within the table size.
            let mut cur = p.parent;
            let mut steps = 0;
            while let Some(k) = cur {
                prop_assert!(k != p.key, "cycle through {:?}", p.key);
                steps += 1;
                prop_assert!(steps <= s.len());
                cur = s.get(&k).and_then(|x| x.parent);
            }
            prop_assert_eq!(p.n_open, opens.get(&p.key).copied().unwrap_or(0));
            prop_assert_eq!(p.n_conn, conns.get(&p.key).copied().unwrap_or(0));
        }
        prop_assert_eq!(s.live_count() + s.exited_count(), s.len());
        prop_assert_eq!(s.procs().filter(|p| p.is_live()).count(), s.live_count());
    }
}

#[test]
fn a_forked_child_inherits_the_parents_verified_facts() {
    use candor_core::Input;
    use candor_proto::{BStr, Event, EventKind, ProcKey};
    let parent = ProcKey {
        tgid: 1,
        start_ticks: 9,
    };
    let child = ProcKey {
        tgid: 50,
        start_ticks: 99,
    };
    let mut s = candor_core::State::new();
    let ev = |id, p: ProcKey, kind| Event {
        id,
        ts_ns: id * 1000,
        proc: p,
        tid: p.tgid,
        uid: 0,
        kind,
    };
    s.apply(&Input::RawEvent {
        event: ev(
            1,
            parent,
            EventKind::Exec {
                exe: BStr::from("/usr/lib/systemd/systemd"),
                argv: BStr::from("/sbin/init"),
                argv_trunc: false,
                fileless: false,
                dev: 1,
                ino: 2,
            },
        ),
    });
    s.apply(&Input::ExeMeta {
        proc: parent,
        trusted: true,
        system_dir: true,
        home: BStr::from("/root"),
        world_writable_dir: false,
        script_trusted: false,
        private_view: false,
    });
    s.apply(&Input::RawEvent {
        event: ev(2, parent, EventKind::Fork { child }),
    });
    let c = s.get(&child).unwrap();
    assert!(c.exe_trusted && c.exe_system);
    assert_eq!(c.exe.as_bytes(), b"/usr/lib/systemd/systemd");
}

#[test]
fn per_process_syscall_table_is_capped() {
    let mut s = State::new();
    let p = key(5);
    s.apply_event(&ev(1, 1, p, open("/etc/hosts", 1)));
    let stat = |nr: u32| SysStat {
        nr,
        name: format!("sys{nr}"),
        count: 1,
        lat_count: 0,
        lat_total_ns: 0,
        lat_max_ns: 0,
    };
    let totals = (0..(PER_PROC_SYSCALLS as u32 + 1000))
        .map(|nr| (p, stat(nr)))
        .collect();
    s.apply(&Input::SysTotals { ts_ns: 2, totals });
    assert_eq!(s.get(&p).unwrap().syscalls.len(), PER_PROC_SYSCALLS);
    // A number already in the table is still updated at the cap.
    let mut again = stat(0);
    again.count = 7;
    s.apply(&Input::SysTotals {
        ts_ns: 3,
        totals: vec![(p, again)],
    });
    assert_eq!(s.get(&p).unwrap().syscalls[&0].count, 7);
    assert_eq!(s.get(&p).unwrap().syscalls.len(), PER_PROC_SYSCALLS);
}
