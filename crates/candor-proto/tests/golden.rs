//! Golden files pin the JSON encoding of every message type (plan 4.5).
//! Changing a file under fixtures/proto/v1 requires bumping PROTO_VERSION.
//! A missing file is written only when CANDOR_BLESS=1 is set; an existing
//! file is never rewritten by this test.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use candor_proto::{PROTO_VERSION, decode_client, decode_daemon};
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/proto")
        .join(format!("v{PROTO_VERSION}"))
}

fn check(name: &str, json: String) -> String {
    let path = dir().join(format!("{name}.json"));
    match std::fs::read_to_string(&path) {
        Ok(on_disk) => {
            assert_eq!(
                on_disk.trim_end(),
                json,
                "golden file {} differs",
                path.display()
            );
            on_disk
        }
        Err(_) if std::env::var("CANDOR_BLESS").as_deref() == Ok("1") => {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(&path, format!("{json}\n")).unwrap();
            json
        }
        Err(e) => panic!("missing golden file {}: {e}", path.display()),
    }
}

#[test]
fn client_messages_match_golden_files() {
    for (name, msg) in common::client_samples() {
        let on_disk = check(name, serde_json::to_string_pretty(&msg).unwrap());
        assert_eq!(decode_client(on_disk.as_bytes()).unwrap(), msg, "{name}");
    }
}

#[test]
fn daemon_messages_match_golden_files() {
    for (name, msg) in common::daemon_samples() {
        let on_disk = check(name, serde_json::to_string_pretty(&msg).unwrap());
        assert_eq!(decode_daemon(on_disk.as_bytes()).unwrap(), msg, "{name}");
    }
}

#[test]
fn every_message_type_has_exactly_one_golden_file() {
    let mut names: Vec<String> = std::fs::read_dir(dir())
        .unwrap()
        .map(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .trim_end_matches(".json")
                .to_string()
        })
        .collect();
    names.sort();
    let mut expected: Vec<String> = candor_proto::msg::CLIENT_TYPES
        .iter()
        .chain(candor_proto::msg::DAEMON_TYPES)
        .map(|s| s.to_string())
        .collect();
    expected.sort();
    assert_eq!(names, expected);
}
