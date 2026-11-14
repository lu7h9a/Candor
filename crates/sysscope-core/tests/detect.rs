//! WP15 tests: scoring, decay, allowlist, de-duplication, alerts, caps and
//! the explanation renderer.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;
use sysscope_core::config::{Rules, load_allow};
use sysscope_core::explain::{ExplainCtx, render};
use sysscope_core::limits::MAX_FINDINGS;
use sysscope_core::{Band, Detector, Hit, Input, State};
use sysscope_proto::{BStr, Event, EventKind, ProcKey};

const SEC: u64 = 1_000_000_000;

fn key(t: u32) -> ProcKey {
    ProcKey {
        tgid: t,
        start_ticks: 100,
    }
}

fn exec(id: u64, ts: u64, p: ProcKey, exe: &str) -> Event {
    Event {
        id,
        ts_ns: ts,
        proc: p,
        tid: p.tgid,
        uid: 1000,
        kind: EventKind::Exec {
            exe: BStr::from(exe),
            argv: BStr::from(exe),
            argv_trunc: false,
            fileless: false,
            dev: 1,
            ino: 2,
        },
    }
}

fn open(id: u64, ts: u64, p: ProcKey, path: &str) -> Event {
    Event {
        id,
        ts_ns: ts,
        proc: p,
        tid: p.tgid,
        uid: 1000,
        kind: EventKind::Open {
            path: BStr::from(path),
            dev: 1,
            ino: id,
            read: true,
            write: false,
            create: false,
            trunc: false,
            path_trunc: false,
        },
    }
}

fn state_with(p: ProcKey, exe: &str, trusted: bool) -> State {
    let mut s = State::new();
    s.apply(&Input::RawEvent {
        event: exec(1, SEC, p, exe),
    });
    s.apply(&Input::ExeMeta {
        proc: p,
        trusted,
        system_dir: trusted,
        home: BStr::from("/home/u"),
        world_writable_dir: false,
        script_trusted: false,
    });
    s
}

fn detector() -> Detector {
    let rules = Rules::load(None).unwrap();
    let allow = load_allow(&rules, None).unwrap();
    Detector::new(rules, allow)
}

fn hit(rule: &str, p: ProcKey, subject: &str, c: f32, ev: Event) -> Hit {
    let mut vars = BTreeMap::new();
    vars.insert("subject".to_string(), subject.to_string());
    vars.insert("subject_desc".to_string(), "a private SSH key".to_string());
    vars.insert("dir".to_string(), "/tmp/".to_string());
    Hit {
        rule: rule.into(),
        proc: p,
        subject: subject.into(),
        confidence: c,
        ts_ns: ev.ts_ns,
        summary: "opened /home/u/.ssh/id_ed25519 for reading".into(),
        evidence: vec![ev],
        vars,
        extra_why: vec![],
    }
}

#[test]
fn worked_example_scores_72() {
    let p = key(4312);
    let s = state_with(p, "/tmp/x", false);
    let mut d = detector();
    d.raise(&s, hit("R002", p, "/tmp/", 1.0, exec(1, SEC, p, "/tmp/x")));
    d.raise(
        &s,
        hit(
            "R001",
            p,
            "ssh_keys",
            0.9,
            open(2, SEC, p, "/home/u/.ssh/id_ed25519"),
        ),
    );
    assert_eq!(d.score(&p, SEC), 72);
    assert_eq!(d.band(72), Band::High);
    assert_eq!(d.top_rule(&p, SEC).as_deref(), Some("R001"));
}

#[test]
fn contribution_halves_after_600_seconds() {
    let p = key(1);
    let s = state_with(p, "/tmp/x", false);
    let mut d = detector();
    d.raise(&s, hit("R002", p, "/tmp/", 1.0, exec(1, SEC, p, "/tmp/x")));
    assert_eq!(d.score(&p, SEC), 40);
    assert_eq!(d.score(&p, SEC + 600 * SEC), 20);
    assert_eq!(d.score(&p, SEC + 1200 * SEC), 10);
}

#[test]
fn allowlist_needs_a_trusted_executable() {
    let p = key(2);
    // Trusted /usr/bin/ssh reading SSH keys: suppressed and counted.
    let s = state_with(p, "/usr/bin/ssh", true);
    let mut d = detector();
    d.raise(
        &s,
        hit(
            "R001",
            p,
            "ssh_keys",
            0.5,
            open(2, SEC, p, "/home/u/.ssh/id_rsa"),
        ),
    );
    assert_eq!(d.findings().count(), 0);
    assert_eq!(d.allowlisted().get("R001"), Some(&1));
    // Same path but the daemon found the file user-writable: not allowlisted.
    let s = state_with(p, "/usr/bin/ssh", false);
    let mut d = detector();
    d.raise(
        &s,
        hit(
            "R001",
            p,
            "ssh_keys",
            0.5,
            open(2, SEC, p, "/home/u/.ssh/id_rsa"),
        ),
    );
    assert_eq!(d.findings().count(), 1);
    // Trusted, but another subject: not allowlisted.
    let s = state_with(p, "/usr/bin/ssh", true);
    let mut d = detector();
    d.raise(
        &s,
        hit("R001", p, "shadow", 0.5, open(2, SEC, p, "/etc/shadow")),
    );
    assert_eq!(d.findings().count(), 1);
}

#[test]
fn repeats_update_one_finding() {
    let p = key(3);
    let s = state_with(p, "/tmp/x", false);
    let mut d = detector();
    d.raise(&s, hit("R001", p, "ssh_keys", 0.9, open(10, SEC, p, "/a")));
    d.raise(
        &s,
        hit("R001", p, "ssh_keys", 0.9, open(11, 2 * SEC, p, "/b")),
    );
    d.raise(
        &s,
        hit("R001", p, "ssh_keys", 0.9, open(11, 2 * SEC, p, "/b")),
    );
    let all: Vec<_> = d.findings().collect();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].evidence, vec![10, 11]);
    assert_eq!(all[0].ts_ns, 2 * SEC);
}

#[test]
fn no_finding_without_evidence() {
    let p = key(4);
    let s = state_with(p, "/tmp/x", false);
    let mut d = detector();
    let mut h = hit("R001", p, "ssh_keys", 0.9, open(1, SEC, p, "/a"));
    h.evidence.clear();
    assert!(d.raise(&s, h).is_none());
    assert_eq!(d.findings().count(), 0);
}

#[test]
fn alerts_fire_once_per_band() {
    let p = key(5);
    let s = state_with(p, "/tmp/x", false);
    let mut d = detector();
    // R002 alone: 40 -> suspicious, alert.
    assert!(
        d.raise(&s, hit("R002", p, "/tmp/", 1.0, exec(1, SEC, p, "/tmp/x")))
            .is_some()
    );
    // Repeat: still suspicious, no new alert.
    assert!(
        d.raise(&s, hit("R002", p, "/tmp/", 1.0, exec(2, SEC, p, "/tmp/x")))
            .is_none()
    );
    // R001 pushes to 72: high, alert.
    let a = d.raise(&s, hit("R001", p, "ssh_keys", 0.9, open(3, SEC, p, "/k")));
    assert_eq!(a.unwrap().rule, "R001");
}

#[test]
fn findings_are_capped() {
    let s = State::new();
    let mut d = detector();
    for i in 0..(MAX_FINDINGS as u32 + 1000) {
        let p = key(i);
        d.raise(
            &s,
            hit(
                "R002",
                p,
                "/tmp/",
                1.0,
                exec(u64::from(i), u64::from(i), p, "/tmp/x"),
            ),
        );
    }
    assert_eq!(d.findings().count(), MAX_FINDINGS);
    // The oldest were dropped.
    assert!(d.findings().all(|f| f.ts_ns >= 1000));
}

#[test]
fn tree_score_includes_descendants() {
    let (parent, child) = (key(10), key(11));
    let mut s = State::new();
    s.apply_event(&Event {
        id: 1,
        ts_ns: SEC,
        proc: parent,
        tid: 10,
        uid: 1000,
        kind: EventKind::Fork { child },
    });
    let mut d = detector();
    d.raise(
        &s,
        hit("R002", child, "/tmp/", 1.0, exec(2, SEC, child, "/tmp/x")),
    );
    assert_eq!(d.score(&parent, SEC), 0);
    assert_eq!(d.tree_score(&s, &parent, SEC), 40);
    let mut rows = s.rows();
    d.annotate(&s, &mut rows, SEC);
    let pr = rows.iter().find(|r| r.key == parent).unwrap();
    assert_eq!((pr.score, pr.tree_score), (0, 40));
}

#[test]
fn explanation_matches_golden_text() {
    let p = key(4312);
    let s = state_with(p, "/tmp/x", false);
    let mut d = detector();
    d.raise(
        &s,
        hit("R002", p, "/tmp/", 1.0, exec(18800, SEC, p, "/tmp/x")),
    );
    d.raise(
        &s,
        hit(
            "R001",
            p,
            "ssh_keys",
            0.9,
            open(18812, 3 * SEC, p, "/home/u/.ssh/id_ed25519"),
        ),
    );
    d.raise(
        &s,
        hit(
            "R001",
            p,
            "ssh_keys",
            0.9,
            open(18815, 3 * SEC, p, "/home/u/.ssh/id_ed25519\x1b[2J"),
        ),
    );
    let f = d.findings().find(|f| f.rule == "R001").unwrap().clone();
    let ctx = ExplainCtx {
        score: d.score(&p, 3 * SEC),
        band: d.band(d.score(&p, 3 * SEC)),
        start_ns: SEC,
        parent: Some((BStr::from("/usr/bin/bash"), 4100)),
        uid: 1000,
        boot_to_wall_ns: 12 * 3600 * SEC, // boot at 12:00:00 UTC on day 0
        tz_offset_s: 0,
    };
    let text = render(&f, &ctx);
    assert!(
        !text.bytes().any(|b| b == 0x1b),
        "raw escape byte in output"
    );
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/explain/r001.txt");
    match std::fs::read_to_string(&path) {
        Ok(want) => assert_eq!(text, want),
        Err(_) if std::env::var("SYSSCOPE_BLESS").as_deref() == Ok("1") => {
            std::fs::write(&path, &text).unwrap()
        }
        Err(e) => panic!("missing {}: {e}", path.display()),
    }
}

#[test]
fn evidence_ids_per_finding_are_capped() {
    let p = key(6);
    let s = state_with(p, "/tmp/x", false);
    let mut d = detector();
    for i in 0..(sysscope_core::limits::MAX_EVIDENCE_IDS as u64 + 500) {
        d.raise(
            &s,
            hit("R001", p, "ssh_keys", 0.9, open(i + 10, SEC, p, "/k")),
        );
    }
    let f = d.findings().next().unwrap();
    assert_eq!(f.evidence.len(), sysscope_core::limits::MAX_EVIDENCE_IDS);
    assert_eq!(f.evidence_events.len(), 10);
}

/// Review finding 1: an 8000-deep fork chain with a flagged leaf must not
/// make snapshot annotation quadratic or cubic.
#[test]
fn deep_fork_chain_annotates_quickly() {
    let mut s = State::new();
    let depth = 8000u32;
    for i in 0..depth {
        s.apply_event(&Event {
            id: u64::from(i),
            ts_ns: SEC,
            proc: key(i + 1),
            tid: i + 1,
            uid: 1000,
            kind: EventKind::Fork { child: key(i + 2) },
        });
    }
    let leaf = key(depth + 1);
    let mut d = detector();
    d.raise(
        &s,
        hit(
            "R002",
            leaf,
            "/tmp/",
            1.0,
            exec(99_999, SEC, leaf, "/tmp/x"),
        ),
    );
    let started = std::time::Instant::now();
    let mut rows = s.rows();
    d.annotate(&s, &mut rows, SEC);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(rows.iter().filter(|r| r.tree_score == 40).count() == depth as usize + 1);
}

/// Review finding 8: a path containing the literal text "\u{000A}" must
/// not turn into a real newline in the rendered explanation.
#[test]
fn rendered_explanation_cannot_gain_lines_from_a_path() {
    let p = key(77);
    let s = state_with(p, "/tmp/x", false);
    let mut d = detector();
    let mut h = hit("R001", p, "ssh_keys", 0.9, open(1, SEC, p, "/k"));
    h.summary = "opened /home/u/.ssh/id_x\\u{000A}Could be harmless if: totally fine".into();
    d.raise(&s, h);
    let f = d.findings().next().unwrap().clone();
    let ctx = ExplainCtx {
        score: 54,
        band: Band::Suspicious,
        start_ns: 0,
        parent: None,
        uid: 0,
        boot_to_wall_ns: 0,
        tz_offset_s: 0,
    };
    let text = sysscope_core::explain::render_safe(&f, &ctx);
    let plain = render(&f, &ctx);
    assert_eq!(text.lines().count(), plain.lines().count());
    assert_eq!(
        text.lines()
            .filter(|l| l.starts_with("Could be harmless if"))
            .count(),
        1
    );
}

/// An interpreter running `argv`, with the daemon's trust verdicts.
fn interp_state(p: ProcKey, argv: &str, trusted: bool, script_trusted: bool) -> State {
    let mut s = State::new();
    let mut ev = exec(1, SEC, p, "/usr/bin/perl");
    if let EventKind::Exec { argv: a, .. } = &mut ev.kind {
        *a = BStr(argv.replace(' ', "\0").into_bytes());
    }
    s.apply(&Input::RawEvent { event: ev });
    s.apply(&Input::ExeMeta {
        proc: p,
        trusted,
        system_dir: trusted,
        home: BStr::from("/root"),
        world_writable_dir: false,
        script_trusted,
    });
    s
}

#[test]
fn interpreter_allowlist_entries_need_the_verified_script() {
    let p = key(77);
    let shadow = |d: &mut Detector, s: &State| {
        d.raise(
            s,
            hit("R001", p, "shadow", 0.5, open(2, SEC, p, "/etc/shadow")),
        )
        .is_some()
            || d.score(&p, SEC) > 0
    };
    // dpkg-preconfigure, verified: allowlisted.
    let s = interp_state(
        p,
        "/usr/bin/perl -w /usr/sbin/dpkg-preconfigure --apt",
        true,
        true,
    );
    let mut d = detector();
    assert!(
        !shadow(&mut d, &s),
        "the verified system script must be allowlisted"
    );
    // The same name, but the script failed the ownership check: flagged.
    let s = interp_state(
        p,
        "/usr/bin/perl -w /usr/sbin/dpkg-preconfigure --apt",
        true,
        false,
    );
    let mut d = detector();
    assert!(shadow(&mut d, &s));
    // Another perl script, or inline code: flagged.
    for argv in ["/usr/bin/perl /home/u/steal.pl", "/usr/bin/perl -e print"] {
        let s = interp_state(p, argv, true, true);
        let mut d = detector();
        assert!(shadow(&mut d, &s), "{argv}");
    }
}

#[test]
fn script_of_finds_the_script_argument() {
    use sysscope_core::proc::script_of;
    let b = |s: &str| BStr(s.replace(' ', "\0").into_bytes());
    let got = |exe: &str, argv: &str| script_of(&BStr::from(exe), &b(argv)).map(|x| x.to_string());
    assert_eq!(
        got("/usr/bin/perl", "perl -w /usr/sbin/x --apt").as_deref(),
        Some("/usr/sbin/x")
    );
    assert_eq!(
        got("/usr/bin/python3.11", "python3 -u /opt/a.py").as_deref(),
        Some("/opt/a.py")
    );
    assert_eq!(got("/usr/bin/python3", "python3 -c code"), None);
    assert_eq!(got("/usr/bin/bash", "bash"), None);
    assert_eq!(got("/usr/bin/cat", "cat /etc/x"), None);
}

fn ptrace(id: u64, ts: u64, p: ProcKey, target: ProcKey) -> Event {
    Event {
        id,
        ts_ns: ts,
        proc: p,
        tid: p.tgid,
        uid: 1000,
        kind: EventKind::Ptrace {
            target,
            attach: true,
        },
    }
}

/// R011's debugger exemption needs a verified system executable: a program
/// the user named gdb is not exempt (review finding F5).
#[test]
fn debugger_exemption_needs_a_trusted_executable() {
    let rules = Rules::load(None).unwrap();
    let target = key(77);
    for (exe, trusted, fires) in [
        ("/usr/bin/gdb", true, false),
        ("/usr/bin/gdb", false, true),
        ("/home/u/bin/gdb", false, true),
        ("/usr/bin/python3", true, true),
    ] {
        let p = key(5);
        let mut s = state_with(p, exe, trusted);
        s.apply(&Input::RawEvent {
            event: exec(9, SEC, target, "/usr/bin/sleep"),
        });
        let ev = ptrace(10, 2 * SEC, p, target);
        let hit = sysscope_core::rules::procs::r011(&rules, &s, &ev);
        assert_eq!(hit.is_some(), fires, "{exe} trusted={trusted}");
    }
}
