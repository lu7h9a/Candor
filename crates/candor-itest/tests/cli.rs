//! WP13 CLI: drives `candor` against the daemon and against a recording.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::process::{Command, Output};
use std::time::Duration;
use candor_itest::{Daemon, bin_dir, wl};

fn cli(args: &[&str]) -> Output {
    Command::new(bin_dir().join("candor"))
        .args(args)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn exit_code_3_when_no_daemon_runs() {
    let o = cli(&["status"]);
    assert_eq!(
        o.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("not running"));
    assert_eq!(cli(&["nonsense"]).status.code(), Some(2));
}

#[test]
fn status_top_tree_and_json() {
    let d = Daemon::start(&[]).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    let o = cli(&["status"]);
    assert!(o.status.success());
    assert!(text(&o).contains("mode: system-wide"), "{}", text(&o));
    let o = cli(&["top", "-n", "5"]);
    assert!(o.status.success() && text(&o).contains("PID"));
    let o = cli(&["tree"]);
    assert!(o.status.success() && !text(&o).is_empty());
    let o = cli(&["--json", "top", "-n", "3"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 3);
    assert!(d.stop().unwrap().success());
}

#[test]
fn hostile_file_names_are_escaped_in_output() {
    let d = Daemon::start(&[]).unwrap();
    let tail = std::thread::spawn(|| cli(&["tail", "--seconds", "6"]));
    std::thread::sleep(Duration::from_secs(1));
    wl(&["badname"]).unwrap();
    let o = tail.join().unwrap();
    let out = o.stdout;
    assert!(!out.contains(&0x1b), "raw ESC byte reached the terminal");
    assert!(
        !out.iter().any(|&b| b < 0x20 && b != b'\n'),
        "raw control byte"
    );
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("\\x1B[31mred"), "escaped name not shown");
    assert!(d.stop().unwrap().success());
}

fn secret_finding_setup() -> std::path::PathBuf {
    // A program in /tmp (R002) that reads a "private key" under root's home
    // (R001) with secrets in its command line.
    // Literal /tmp, not $TMPDIR: R002 is about /tmp (WP29 runs the itests
    // with TMPDIR elsewhere).
    let dir = std::path::PathBuf::from("/tmp/candor-cli-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join("tool");
    std::fs::copy(bin_dir().join("candor-wl"), &exe).unwrap();
    std::fs::create_dir_all("/root/.ssh").unwrap();
    std::fs::write("/root/.ssh/id_candor_test", "fake key for the CLI test\n").unwrap();
    exe
}

#[test]
fn export_is_redacted_by_default_and_csv_parses() {
    let d = Daemon::start(&[]).unwrap();
    let exe = secret_finding_setup();
    let out = Command::new(&exe)
        .args([
            "--dir",
            "/tmp/candor-cli-test/d",
            "open-path",
            "/root/.ssh/id_candor_test",
            "sleep",
            "3000",
            "--",
        ])
        .args(["--password=hunter2", "https://bob:pw@example.com/x"])
        .output()
        .unwrap();
    assert!(out.status.success());
    std::thread::sleep(Duration::from_secs(1));
    let o = Command::new(bin_dir().join("candor"))
        .args(["export", "--format", "json"])
        .env("HOME", "/root")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let red = text(&o);
    assert!(
        red.contains("R001") && red.contains("R002"),
        "findings missing: {red}"
    );
    for secret in ["hunter2", "bob:pw", "/root/.ssh"] {
        assert!(
            !red.contains(secret),
            "{secret} leaked into the default export"
        );
    }
    assert!(red.contains("~/.ssh/id_candor_test") && red.contains("<redacted>"));
    // --raw keeps everything and warns.
    let o = Command::new(bin_dir().join("candor"))
        .args(["export", "--format", "json", "--raw"])
        .output()
        .unwrap();
    assert!(text(&o).contains("hunter2") && text(&o).contains("/root/.ssh/id_candor_test"));
    assert!(String::from_utf8_lossy(&o.stderr).contains("warning"));
    // CSV parses with Python's csv module.
    let o = cli(&["export", "--format", "csv"]);
    let csv_path = std::env::temp_dir().join("candor-export.csv");
    std::fs::write(&csv_path, &o.stdout).unwrap();
    let py = Command::new("python3")
        .args(["-c", "import csv,sys; r=list(csv.DictReader(open(sys.argv[1]))); assert len(r) > 10 and 'exe' in r[0]; print(len(r))"])
        .arg(&csv_path)
        .output()
        .unwrap();
    assert!(
        py.status.success(),
        "{}",
        String::from_utf8_lossy(&py.stderr)
    );
    // findings in text form carry the 5.6 explanation.
    let f = text(&cli(&["findings"]));
    assert!(
        f.contains("Why it is flagged:") && f.contains("To silence:"),
        "{f}"
    );
    let _ = std::fs::remove_file("/root/.ssh/id_candor_test");
    assert!(d.stop().unwrap().success());
}

#[test]
fn replay_of_a_recording_finds_the_same_rules() {
    let rec = std::env::temp_dir().join("candor-test.events.jsonl");
    let rec_s = rec.to_string_lossy().into_owned();
    let d = Daemon::start(&["--record", &rec_s]).unwrap();
    let exe = secret_finding_setup();
    Command::new(&exe)
        .args([
            "--dir",
            "/tmp/candor-cli-test/d",
            "open-path",
            "/root/.ssh/id_candor_test",
        ])
        .output()
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert!(d.stop().unwrap().success());
    let o = cli(&["replay", &rec_s]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let s = text(&o);
    assert!(
        s.contains("R001 Credential file read") && s.contains("R002"),
        "{s}"
    );
    let _ = std::fs::remove_file("/root/.ssh/id_candor_test");
}
