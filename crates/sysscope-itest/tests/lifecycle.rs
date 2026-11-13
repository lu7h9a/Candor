//! WP05 lifecycle cases: observed EXEC/FORK/EXIT must equal wl's manifest.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use sysscope_itest::{count, run_wl, wl_key};
use sysscope_proto::EventKind;

#[test]
fn exec_100_children_exactly() {
    let (m, ev) = run_wl(&["exec", "100"]).unwrap();
    let root = wl_key(&m);
    let exe = m["actions"][0]["exe"].as_str().unwrap().to_string();
    let forks = ev
        .iter()
        .filter(|e| e.proc == root && matches!(e.kind, EventKind::Fork { .. }));
    assert_eq!(forks.count(), 100);
    let children: Vec<_> = ev.iter().filter(|e| e.proc != root).collect();
    let execs: Vec<_> = children
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::Exec { exe, .. } => Some(exe.escaped()),
            _ => None,
        })
        .collect();
    assert_eq!(execs.len(), 100);
    assert!(
        execs.iter().all(|x| *x == exe),
        "exe paths: {:?}",
        &execs[..3]
    );
    assert_eq!(
        children
            .iter()
            .filter(|e| matches!(e.kind, EventKind::Exit {}))
            .count(),
        100
    );
    // wl itself: exactly one exec (into wl) is not seen (it started before
    // tracing); exactly one exit.
    assert_eq!(
        ev.iter()
            .filter(|e| e.proc == root && matches!(e.kind, EventKind::Exit {}))
            .count(),
        1
    );
}

#[test]
fn fork_100_without_exec() {
    let (_m, ev) = run_wl(&["fork", "100"]).unwrap();
    assert_eq!(count(&ev, "Fork"), 100);
    assert_eq!(count(&ev, "Exec"), 0);
    assert_eq!(count(&ev, "Exit"), 101); // 100 children + wl
}

#[test]
fn threads_are_not_processes() {
    let (m, ev) = run_wl(&["threads", "10"]).unwrap();
    assert_eq!(count(&ev, "Fork"), 0);
    let root = wl_key(&m);
    let exits: Vec<_> = ev
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Exit {}))
        .collect();
    assert_eq!(exits.len(), 1);
    assert_eq!(exits[0].proc, root);
}

#[test]
fn leader_exiting_first_gives_one_exit_from_the_last_thread() {
    let (m, ev) = run_wl(&["leader-exits-first"]).unwrap();
    let root = wl_key(&m);
    let exits: Vec<_> = ev
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Exit {}))
        .collect();
    assert_eq!(exits.len(), 1, "{exits:?}");
    assert_eq!(exits[0].proc, root);
    // The event comes from the surviving thread, not the leader.
    assert_ne!(exits[0].tid, root.tgid);
}

#[test]
fn memfd_exec_is_fileless() {
    let (_m, ev) = run_wl(&["memfd-exec"]).unwrap();
    let execs: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::Exec { fileless, exe, .. } => Some((*fileless, exe.escaped())),
            _ => None,
        })
        .collect();
    assert_eq!(execs.len(), 1, "{execs:?}");
    assert!(execs[0].0, "memfd exec not flagged fileless: {execs:?}");
}
