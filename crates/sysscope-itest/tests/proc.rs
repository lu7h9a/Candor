//! WP10 /proc sampler: BPF and /proc agree on ProcKey for 200 new processes
//! (plan 4.4 [VERIFY]), CPU % of a busy loop, RSS of a 200 MiB allocation.
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;
use sysscope_core::{Input, State};
use sysscope_itest::{Dump, action, wl, wl_key};
use sysscope_proto::{EventKind, ProcKey};

fn samples(stats: &[serde_json::Value]) -> Vec<Input> {
    stats
        .iter()
        .filter(|v| v["t"] == "Samples")
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .collect()
}

#[test]
fn bpf_and_proc_keys_match_for_200_processes() {
    let dump = Dump::start(&[]).unwrap();
    let m = wl(&["spawn-hold", "200", "2500"]).unwrap();
    let (ev, stats) = dump.stop_full().unwrap();
    let root = wl_key(&m);
    // Keys the BPF side assigned to wl's children.
    let bpf: BTreeMap<u32, ProcKey> = ev
        .iter()
        .filter(|e| e.proc == root)
        .filter_map(|e| match &e.kind {
            EventKind::Fork { child } => Some((child.tgid, *child)),
            _ => None,
        })
        .collect();
    assert_eq!(bpf.len(), 200);
    // Keys the /proc sampler read for the same pids.
    let mut from_proc: BTreeMap<u32, ProcKey> = BTreeMap::new();
    for s in samples(&stats) {
        if let Input::Samples { samples, .. } = s {
            for p in samples {
                if bpf.contains_key(&p.key.tgid) {
                    from_proc.insert(p.key.tgid, p.key);
                }
            }
        }
    }
    assert_eq!(from_proc.len(), 200, "children seen by the sampler");
    let equal = bpf
        .iter()
        .filter(|(t, k)| from_proc.get(t) == Some(k))
        .count();
    assert_eq!(equal, 200, "BPF vs /proc ProcKey");
    // wl itself too (it was started after tracing began).
    let pids: Vec<u64> = action(&m, "spawn-hold")["pids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_u64().unwrap())
        .collect();
    assert!(pids.iter().all(|p| bpf.contains_key(&(*p as u32))));
}

fn state_from(stats: &[serde_json::Value]) -> State {
    let mut st = State::new();
    for i in samples(stats) {
        st.apply(&i);
    }
    st
}

#[test]
fn busy_loop_shows_about_one_core() {
    let dump = Dump::start(&[]).unwrap();
    let m = wl(&["busy", "4000"]).unwrap();
    let (_, stats) = dump.stop_full().unwrap();
    let child = action(&m, "busy")["child"].as_u64().unwrap() as u32;
    let st = state_from(&stats);
    let p = st
        .procs()
        .find(|p| p.key.tgid == child)
        .expect("busy child sampled");
    // Points after the first sample (which has no previous one to diff).
    let cpu: Vec<f32> = p.series.iter().skip(1).map(|s| s.1).collect();
    assert!(cpu.len() >= 2, "{cpu:?}");
    let full = cpu.iter().filter(|c| (90.0..=110.0).contains(*c)).count();
    assert!(full >= 2, "cpu samples {cpu:?}");
}

#[test]
fn allocation_shows_in_rss_within_ten_percent() {
    let dump = Dump::start(&[]).unwrap();
    let m = wl(&["alloc", "200", "3000"]).unwrap();
    let (_, stats) = dump.stop_full().unwrap();
    let a = action(&m, "alloc");
    let child = a["child"].as_u64().unwrap() as u32;
    let bytes = a["bytes"].as_u64().unwrap() as f64;
    let st = state_from(&stats);
    let p = st
        .procs()
        .find(|p| p.key.tgid == child)
        .expect("alloc child sampled");
    let max_rss = p.series.iter().map(|s| s.2).max().unwrap() as f64;
    assert!(
        (max_rss - bytes).abs() <= 0.1 * bytes,
        "rss {max_rss} vs {bytes}"
    );
}
