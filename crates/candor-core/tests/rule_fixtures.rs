//! Replays every fixture under fixtures/rules/<rule>/<case>/ through the
//! engine and compares findings (rule, subject, process, confidence) and
//! scores with expected.json exactly (plan 5.7(1), T3).
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use candor_core::Engine;
use candor_core::replay::replay_engine;
use candor_proto::DaemonMsg;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rules")
}

fn run_case(dir: &std::path::Path) -> Result<(), String> {
    let text = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    let mut engine = Engine::with_defaults().unwrap();
    replay_engine(&mut engine, text.lines()).map_err(|e| e.to_string())?;

    let mut got: Vec<(String, String, u64, String)> = engine
        .detector
        .findings()
        .map(|f| {
            (
                f.rule.clone(),
                f.subject.clone(),
                u64::from(f.proc.tgid),
                format!("{:.2}", f.confidence),
            )
        })
        .collect();
    got.sort();
    let mut want: Vec<(String, String, u64, String)> = expected["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_string(),
                f["subject"].as_str().unwrap().to_string(),
                f["tgid"].as_u64().unwrap(),
                format!("{:.2}", f["confidence"].as_f64().unwrap()),
            )
        })
        .collect();
    want.sort();
    if got != want {
        return Err(format!("findings: got {got:?}, want {want:?}"));
    }
    // Every finding carries evidence (I9).
    if engine.detector.findings().any(|f| f.evidence.is_empty()) {
        return Err("finding without evidence".into());
    }
    let DaemonMsg::Snapshot { procs, .. } = engine.snapshot(0) else {
        unreachable!()
    };
    for (tgid, score) in expected["scores"].as_object().unwrap() {
        let tgid: u32 = tgid.parse().unwrap();
        let row = procs
            .iter()
            .find(|r| r.key.tgid == tgid)
            .ok_or(format!("no process {tgid}"))?;
        if u64::from(row.score) != score.as_u64().unwrap() {
            return Err(format!("score of {tgid}: got {}, want {score}", row.score));
        }
    }
    Ok(())
}

#[test]
fn every_rule_fixture_matches_expected() {
    let mut failures = Vec::new();
    let mut ran = 0;
    for rule in std::fs::read_dir(root()).unwrap() {
        let rule = rule.unwrap().path();
        let (mut pos, mut neg, mut bnd) = (0, 0, 0);
        for case in std::fs::read_dir(&rule).unwrap() {
            let case = case.unwrap().path();
            let name = case.file_name().unwrap().to_string_lossy().to_string();
            if name.starts_with("pos-") {
                pos += 1;
            } else if name.starts_with("neg-") {
                neg += 1;
            } else if name.starts_with("boundary-") {
                bnd += 1;
            }
            ran += 1;
            if let Err(e) = run_case(&case) {
                failures.push(format!("{}: {e}", case.display()));
            }
        }
        assert!(
            pos >= 3 && neg >= 3 && bnd >= 2,
            "{} has {pos}/{neg}/{bnd} pos/neg/boundary",
            rule.display()
        );
    }
    assert!(ran >= 40, "only {ran} fixtures");
    assert!(
        failures.is_empty(),
        "{} failing:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
