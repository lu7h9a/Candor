//! Benign corpus regression (plan 5.7(3), WP18): every recording under
//! fixtures/benign/*.events.jsonl.gz (made by `make fp-eval` in the
//! debian12 test VM, gzip-compressed) is
//! replayed through the default rules; there must be no finding at "high"
//! and at most 2 at "suspicious" per recorded hour.
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

#[test]
fn benign_recordings_stay_within_the_false_positive_budget() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/benign");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(".events.jsonl.gz"))
        .collect();
    files.sort();
    assert!(files.len() >= 5, "only {} benign recordings", files.len());
    let (mut high, mut suspicious, mut seconds) = (Vec::new(), 0usize, 0f64);
    for f in &files {
        let mut text = String::new();
        std::io::Read::read_to_string(
            &mut flate2::read::GzDecoder::new(std::fs::File::open(f).unwrap()),
            &mut text,
        )
        .unwrap();
        let mut e = Engine::with_defaults().unwrap();
        replay_engine(&mut e, text.lines()).unwrap();
        let ts: Vec<u64> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v["event"]["ts_ns"].as_u64())
            .collect();
        if let (Some(a), Some(b)) = (ts.iter().min(), ts.iter().max()) {
            seconds += (b - a) as f64 / 1e9;
        }
        let DaemonMsg::Snapshot { procs, .. } = e.snapshot(0) else {
            unreachable!()
        };
        for fd in e.detector.findings() {
            let score = procs
                .iter()
                .find(|p| p.key == fd.proc)
                .map(|p| p.score)
                .unwrap_or(0);
            if score >= 60 {
                high.push(format!("{}: {} {}", f.display(), fd.rule, fd.summary));
            } else if score >= 30 {
                suspicious += 1;
            }
        }
    }
    assert!(high.is_empty(), "findings at high: {high:?}");
    let hours = (seconds / 3600.0).max(1.0 / 60.0);
    assert!(
        suspicious as f64 <= 2.0 * hours,
        "{suspicious} suspicious findings in {seconds:.0} s"
    );
}
