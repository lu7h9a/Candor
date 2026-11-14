//! WP11: replaying fixtures/core/basic.events.jsonl gives the golden snapshot.
//! A missing golden file is written only with CANDOR_BLESS=1.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use candor_core::replay::{ReplayError, replay};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/core")
}

#[test]
fn basic_replay_matches_golden_snapshot() {
    let text = std::fs::read_to_string(fixtures().join("basic.events.jsonl")).unwrap();
    let state = replay(&text).unwrap();
    let got = serde_json::to_string_pretty(&state.snapshot(0)).unwrap();
    let golden = fixtures().join("basic.snapshot.json");
    match std::fs::read_to_string(&golden) {
        Ok(want) => assert_eq!(got, want.trim_end()),
        Err(_) if std::env::var("CANDOR_BLESS").as_deref() == Ok("1") => {
            std::fs::write(&golden, format!("{got}\n")).unwrap()
        }
        Err(e) => panic!("missing {}: {e}", golden.display()),
    }
}

#[test]
fn bad_recordings_are_errors_not_panics() {
    assert!(matches!(replay(""), Err(ReplayError::BadHeader(_))));
    assert!(matches!(
        replay("{\"x\":1}"),
        Err(ReplayError::BadHeader(_))
    ));
    assert!(matches!(
        replay("{\"candor_record\":2}"),
        Err(ReplayError::Version(2))
    ));
    let e = replay("{\"candor_record\":1}\n{\"t\":\"Nope\"}").unwrap_err();
    assert!(matches!(e, ReplayError::BadLine { line: 2, .. }), "{e}");
}
