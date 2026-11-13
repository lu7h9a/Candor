//! WP08 syscall counts: getppid x 100000 counted exactly (map not full).
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use sysscope_itest::{action, run_wl_sys};

#[test]
fn getppid_is_counted_exactly() {
    let (m, stats) = run_wl_sys(&["syscalls", "getppid", "100000"]).unwrap();
    let nr = action(&m, "syscalls")["nr"].as_u64().unwrap();
    let s = stats
        .iter()
        .find(|s| s["nr"].as_u64() == Some(nr))
        .expect("no getppid counter for wl");
    assert_eq!(s["name"], "getppid");
    assert_eq!(s["count"].as_u64().unwrap(), 100_000, "{s}");
    // Other syscalls of wl are counted too (write of the manifest, exit_group...).
    assert!(stats.iter().any(|s| s["name"] == "write"));
    // System-wide mode: no latency is collected.
    assert!(stats.iter().all(|s| s["lat_count"].as_u64() == Some(0)));
}
