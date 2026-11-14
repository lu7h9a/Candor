//! Replays an events recording from disk and prints a summary. Used to
//! measure replay memory and time (WP11). Prints wall time and the peak
//! resident set size (VmHWM from /proc/self/status, the same number
//! `/usr/bin/time -v` reports as "Maximum resident set size").
// Example binary: unwrap/expect are fine here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::BufRead;

fn main() {
    let started = std::time::Instant::now();
    let path = std::env::args()
        .nth(1)
        .expect("usage: replay_file <file.events.jsonl>");
    let file = std::fs::File::open(&path).expect("open recording");
    let lines = std::io::BufReader::new(file)
        .lines()
        .map(|l| l.expect("read line"));
    let state = candor_core::replay::replay_lines(lines).expect("replay");
    println!(
        "procs={} live={} exited={} global_events={} stats={:?}",
        state.len(),
        state.live_count(),
        state.exited_count(),
        state.global_events().len(),
        state.stats()
    );
    let hwm = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .unwrap_or("VmHWM: ?")
        .to_string();
    println!("elapsed_s={:.2} {hwm}", started.elapsed().as_secs_f64());
}
