//! Rule simulators end to end against the live daemon (plan 5.7(2)): each
//! simulator in testkit/sim runs in a marked scratch directory and the
//! daemon must raise the finding for its rule, with evidence events that
//! belong to the flagged process (WP16 R001-R004, WP17 R005-R008, WP28
//! R009/R011). Where the plan says "the test config adds that dir to the
//! class", the daemon runs with `--dev --rules FILE` (never the installed
//! rules). R012 end to end is the Glasshouse demo (WP24).
//! Simulators come from SYSSCOPE_SIM_DIR, else the repository.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use sysscope_itest::{Client, Daemon, wl, wl_key};
use sysscope_proto::{ClientMsg, DaemonMsg, EventSub, EventSubMode, Finding};

fn sim_dir() -> PathBuf {
    std::env::var_os("SYSSCOPE_SIM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testkit/sim"))
}

/// Runs one simulator and returns the alerts' (rule, summary) seen within 10 s.
fn run_sim(sim: &str) -> Vec<(String, String)> {
    let work = std::env::temp_dir().join(format!("sysscope-e2e-{sim}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join(".sysscope-sim-ok"), "").unwrap();
    let (mut c, _) = Client::hello().unwrap();
    c.send(&ClientMsg::Subscribe {
        snapshots: false,
        alerts: true,
        events: EventSub::Simple(EventSubMode::None),
    })
    .unwrap();
    let st = Command::new("python3")
        .arg(sim_dir().join(sim))
        .arg(&work)
        .status()
        .unwrap();
    assert!(st.success(), "{sim} failed");
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    c.stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    while Instant::now() < deadline {
        if let Ok(DaemonMsg::Alert { finding }) = c.recv() {
            out.push((finding.rule.clone(), finding.summary.clone()));
        }
    }
    let _ = std::fs::remove_dir_all(&work);
    out
}

#[test]
fn r009_viewer_starting_a_shell_is_reported() {
    let d = Daemon::start(&[]).unwrap();
    let alerts = run_sim("doc_spawns_shell.py");
    assert!(
        alerts
            .iter()
            // /bin/sh resolves to the real shell (dash on Debian, bash elsewhere).
            .any(|(r, s)| r == "R009" && s.contains("evince") && s.contains("sh")),
        "{alerts:?}"
    );
    assert!(d.stop().unwrap().success());
}

#[test]
fn r011_attach_to_a_sibling_is_reported() {
    let d = Daemon::start(&[]).unwrap();
    assert!(d.stderr_text().contains("serving"), "{}", d.stderr_text());
    let alerts = run_sim("ptrace_attach.py");
    assert!(
        alerts
            .iter()
            .any(|(r, s)| r == "R011" && s.contains("debugger-level access")),
        "{alerts:?}"
    );
    assert!(d.stop().unwrap().success());
}

/// A marked work directory for one simulator.
fn work(tag: &str) -> PathBuf {
    work_in(&std::env::temp_dir(), tag)
}

/// A fresh simulator work directory under `base`.
fn work_in(base: &std::path::Path, tag: &str) -> PathBuf {
    let w = base.join(format!("sysscope-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&w);
    std::fs::create_dir_all(&w).unwrap();
    std::fs::write(w.join(".sysscope-sim-ok"), "").unwrap();
    w
}

/// A rules override file for `--rules`.
fn rules_file(tag: &str, text: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "sysscope-e2e-rules-{tag}-{}.toml",
        std::process::id()
    ));
    std::fs::write(&p, text).unwrap();
    p
}

/// Runs a simulator in `dir` with extra args; returns every alert seen
/// until `wait` after it finished.
fn sim_alerts(sim: &str, dir: &std::path::Path, args: &[&str], wait: Duration) -> Vec<Finding> {
    let (mut c, _) = Client::hello().unwrap();
    c.send(&ClientMsg::Subscribe {
        snapshots: false,
        alerts: true,
        events: EventSub::Simple(EventSubMode::None),
    })
    .unwrap();
    let st = Command::new("python3")
        .arg(sim_dir().join(sim))
        .arg(dir)
        .args(args)
        .status()
        .unwrap();
    assert!(st.success(), "{sim} failed");
    c.stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut out = Vec::new();
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if let Ok(DaemonMsg::Alert { finding }) = c.recv() {
            out.push(finding);
        }
    }
    out
}

/// The finding of `rule` (with `subject` if given), checked for evidence:
/// non-empty, the full events listed are among the ids, and they belong to
/// the flagged process (window rules may cite its children too).
fn expect(found: &[Finding], rule: &str, subject: Option<&str>) -> Finding {
    let f = found
        .iter()
        .find(|f| f.rule == rule && subject.is_none_or(|s| f.subject == s))
        .unwrap_or_else(|| {
            panic!(
                "no {rule} finding; got {:?}",
                found
                    .iter()
                    .map(|f| (&f.rule, &f.subject))
                    .collect::<Vec<_>>()
            )
        })
        .clone();
    assert!(!f.evidence.is_empty(), "{rule}: no evidence ids");
    assert!(!f.evidence_events.is_empty(), "{rule}: no evidence events");
    for e in &f.evidence_events {
        assert!(
            f.evidence.contains(&e.id),
            "{rule}: event {} not in evidence ids",
            e.id
        );
    }
    if !matches!(rule, "R005" | "R006" | "R007" | "R008") {
        assert!(
            f.evidence_events.iter().all(|e| e.proc == f.proc),
            "{rule}: evidence from another process"
        );
    }
    f
}

#[test]
fn r001_and_r004_with_the_sim_dirs_added_to_their_classes() {
    let (cred, persist) = (work("cred"), work("persist"));
    let rules = rules_file(
        "classes",
        &format!(
            "[[credentials]]\nsubject = \"sim_ssh\"\ndesc = \"a simulator key\"\npaths = [\"{}/.ssh/id_*\"]\nexclude_suffix = [\".pub\"]\n\n[[persistence]]\nsubject = \"sim_rc\"\ndesc = \"a simulator startup file\"\npaths = [\"{}/.bashrc\"]\n",
            cred.display(),
            persist.display()
        ),
    );
    let d = Daemon::start(&["--rules", rules.to_str().unwrap()]).unwrap();
    let a = sim_alerts("cred_read.py", &cred, &[], Duration::from_secs(4));
    let f = expect(&a, "R001", Some("sim_ssh"));
    assert!(f.summary.contains("id_ed25519"), "{}", f.summary);
    let a = sim_alerts("persist_write.py", &persist, &[], Duration::from_secs(4));
    let f = expect(&a, "R004", Some("sim_rc"));
    assert!(f.summary.contains(".bashrc"), "{}", f.summary);
    assert!(d.stop().unwrap().success());
    for p in [cred, persist, rules] {
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::remove_file(&p);
    }
}

#[test]
fn r002_temp_exec_and_r003_fileless_exec() {
    let d = Daemon::start(&[]).unwrap();
    // Literal /tmp, not $TMPDIR: R002 is about /tmp (WP29 runs the itests
    // with TMPDIR elsewhere).
    let w = work_in(std::path::Path::new("/tmp"), "tmpexec");
    let a = sim_alerts("tmp_exec.py", &w, &[], Duration::from_secs(4));
    expect(&a, "R002", Some("/tmp/"));
    let a = sim_alerts("memfd_exec.py", &w, &[], Duration::from_secs(4));
    expect(&a, "R003", Some("fileless"));
    assert!(d.stop().unwrap().success());
    let _ = std::fs::remove_dir_all(&w);
}

#[test]
fn r005_mass_rewrite_with_the_sim_dir_as_user_data() {
    let w = work("ransom");
    let rules = rules_file(
        "ransom",
        &format!("[rules.R005]\nroots = [\"{}/\"]\n", w.display()),
    );
    let d = Daemon::start(&["--rules", rules.to_str().unwrap()]).unwrap();
    let a = sim_alerts("ransom_sim.py", &w, &["25"], Duration::from_secs(4));
    let f = expect(&a, "R005", None);
    assert!(f.evidence.len() >= 20, "{} evidence ids", f.evidence.len());
    assert!(d.stop().unwrap().success());
    let _ = std::fs::remove_dir_all(&w);
    let _ = std::fs::remove_file(&rules);
}

#[test]
fn r006_beaconing_with_the_test_only_loopback_override() {
    // Owner's Q3 answer A: the shipped R006 ignores loopback; this test's
    // rules let it count 127.0.0.1. 14 connects 5 s apart span 65 s (the
    // rule needs >= 60 s; the plan's "8 at 5 s" spans only 35 s).
    let w = work("beacon");
    let rules = rules_file("beacon", "[rules.R006]\ninclude_loopback = true\n");
    let d = Daemon::start(&["--rules", rules.to_str().unwrap()]).unwrap();
    let a = sim_alerts("beacon.py", &w, &["14", "5"], Duration::from_secs(4));
    let f = expect(&a, "R006", None);
    assert!(f.evidence.len() >= 6, "{} evidence ids", f.evidence.len());
    assert!(d.stop().unwrap().success());
    // And the shipped rules stay quiet for loopback.
    let d = Daemon::start(&[]).unwrap();
    let a = sim_alerts("beacon.py", &w, &["7", "1"], Duration::from_secs(2));
    assert!(
        !a.iter().any(|f| f.rule == "R006"),
        "loopback counted by default"
    );
    assert!(d.stop().unwrap().success());
    let _ = std::fs::remove_dir_all(&w);
    let _ = std::fs::remove_file(&rules);
}

#[test]
fn r007_port_scan() {
    let d = Daemon::start(&[]).unwrap();
    let w = work("scan");
    let a = sim_alerts(
        "portscan.py",
        &w,
        &["20000", "20200"],
        Duration::from_secs(4),
    );
    expect(&a, "R007", None);
    assert!(d.stop().unwrap().success());
    let _ = std::fs::remove_dir_all(&w);
}

#[test]
fn r008_event_flood_with_a_small_budget() {
    // A small per-process budget makes the flood last more than the
    // rule's 3 consecutive seconds of drops.
    let d = Daemon::start(&["--budget", "100/200"]).unwrap();
    let m = wl(&["flood", "4000000"]).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let (mut c, _) = Client::hello().unwrap();
    c.send(&ClientMsg::GetDetail {
        proc: wl_key(&m),
        maps: false,
    })
    .unwrap();
    let findings = match c
        .recv_until(|m| matches!(m, DaemonMsg::Detail { .. }))
        .unwrap()
    {
        DaemonMsg::Detail { findings, .. } => findings,
        _ => unreachable!(),
    };
    expect(&findings, "R008", None);
    assert!(d.stop().unwrap().success());
}
