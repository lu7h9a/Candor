//! Rule simulators end to end against the live daemon (plan 5.7(2)): each
//! simulator in testkit/sim runs in a marked scratch directory and the
//! daemon must raise an alert for its rule. WP28: R009 and R011.
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
use sysscope_itest::{Client, Daemon};
use sysscope_proto::{ClientMsg, DaemonMsg, EventSub, EventSubMode};

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
