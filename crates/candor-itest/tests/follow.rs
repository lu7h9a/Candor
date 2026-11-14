//! WP09 follow mode and budgets, and the WP08 latency check (needs follow).
// Integration tests are test code: unwrap/expect/panic are allowed here (SKILL.md 5).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use candor_itest::{
    Dump, PausedWl, action, drops_of, manifest_id, subtree, sysstats_of, wl, wl_key,
};
use candor_proto::{EventKind, ProcKey};

#[test]
fn follow_covers_three_generations_and_ignores_others() {
    let root = PausedWl::start(&["gen3"]).unwrap();
    let pid = root.pid().to_string();
    let dump = Dump::start(&["--follow", &pid]).unwrap();
    assert!(
        dump.stderr_text().contains("following pid"),
        "{}",
        dump.stderr_text()
    );
    let m = root.release().unwrap();
    let other = wl(&["open-read", "100"]).unwrap();
    let ev = dump.stop().unwrap();

    let rk = wl_key(&m);
    let tree = subtree(rk, &ev);
    // Everything recorded belongs to the followed tree.
    let strays: Vec<_> = ev.iter().filter(|e| !tree.contains(&e.proc)).collect();
    assert!(
        strays.is_empty(),
        "events outside the followed tree: {:?}",
        &strays[..strays.len().min(3)]
    );
    // The unrelated wl produced nothing.
    assert!(ev.iter().all(|e| e.proc.tgid != wl_key(&other).tgid));
    // One open of gen-1, gen-2, gen-3, each from a different descendant.
    let mut openers: Vec<ProcKey> = Vec::new();
    for n in 1..=3 {
        let name = format!("/gen-{n}");
        let hits: Vec<_> = ev
            .iter()
            .filter(|e| matches!(&e.kind, EventKind::Open { path, .. } if path.as_bytes().ends_with(name.as_bytes())))
            .collect();
        assert_eq!(hits.len(), 1, "gen-{n}");
        assert_ne!(hits[0].proc, rk);
        openers.push(hits[0].proc);
    }
    openers.sort();
    openers.dedup();
    assert_eq!(openers.len(), 3, "three different generations");
}

/// `neighbour_lossless`: plan WP09 (b) - with the normal ring buffer a
/// second process loses nothing. With a 64 KiB ring (c) the ring is shared
/// and can overflow for everyone; then the neighbour's losses must be fully
/// counted instead.
fn flood_identity(extra: &[&str], neighbour_lossless: bool) {
    let dump = Dump::start(extra).unwrap();
    let busy = std::thread::spawn(|| wl(&["flood", "200000", "sleep", "2500"]).unwrap());
    let calm = wl(&["open-read", "1000"]).unwrap();
    let flood = busy.join().unwrap();
    let (ev, stats) = dump.stop_full().unwrap();

    // Exact identity over every event of the flood process (owner's choice
    // A, WP31): the per-process drop counters count drops of any of its
    // events, so the received side counts all of them too. Besides the
    // 200 000 flood opens, wl (statically linked: no loader opens) emits
    // exactly FLOOD_OTHER events: its EXEC, the /proc/self/stat open, the
    // open that creates the flood target, and its EXIT. A tiny ring can drop
    // those as well; before, only the flood opens were counted as received,
    // so such a drop made the sum 200 002.
    const FLOOD_OTHER: u64 = 4;
    let target = manifest_id(&action(&flood, "flood")["file"]);
    let mine: Vec<&candor_proto::Event> =
        ev.iter().filter(|e| e.proc == wl_key(&flood)).collect();
    let flood_opens = mine
        .iter()
        .filter(|e| matches!(&e.kind, EventKind::Open { dev, ino, read: true, write: false, .. } if (*dev, *ino) == target))
        .count() as u64;
    let received = mine.len() as u64;
    let others: Vec<&'static str> = mine
        .iter()
        .filter(|e| !matches!(&e.kind, EventKind::Open { dev, ino, read: true, write: false, .. } if (*dev, *ino) == target))
        .map(|e| candor_itest::kind_name(e))
        .collect();
    // Opens that failed in wl never reached the hook (reported by wl).
    let failed = action(&flood, "flood")["failed"].as_u64().unwrap_or(0);
    let (budget, ring) = drops_of(&stats, wl_key(&flood).tgid);
    let missed = stats
        .iter()
        .find_map(|v| v.get("loss"))
        .and_then(|l| l["missed"].as_u64())
        .unwrap_or(0);
    assert!(
        budget + ring > 0,
        "the flood should have exceeded the budget"
    );
    // Owner's choice A2 (WP31): the kernel also skips a probe run when the
    // probe is already running on that CPU (recursion protection; frequent
    // on fully preemptible kernels) and counts that only per program
    // (Loss.missed), not per process. So: never more than expected; exactly
    // expected when the kernel skipped nothing; otherwise every missing
    // event is covered by the kernel's skip count.
    let expected = 200_000 - failed + FLOOD_OTHER;
    let counted = received + budget + ring;
    let detail = format!(
        "received {received} ({flood_opens} flood opens + other {others:?}) + budget {budget} + ring {ring} = {counted}, expected {expected}; wl failed opens {failed}; kernel-skipped probe runs (all processes) {missed}"
    );
    assert!(counted <= expected, "{detail}");
    assert!(expected - counted <= missed, "{detail}");
    let flood_short = expected - counted;

    // The neighbour lost nothing.
    let calm_target = manifest_id(&action(&calm, "open-read")["file"]);
    let calm_reads = ev
        .iter()
        .filter(|e| matches!(&e.kind, EventKind::Open { dev, ino, write: false, .. } if (*dev, *ino) == calm_target))
        .count();
    let (cb, cr) = drops_of(&stats, wl_key(&calm).tgid);
    // Kernel skips not already used up by the flood may also hit the
    // neighbour (A2).
    let skips_left = missed - flood_short;
    let missing = 1000 - calm_reads as u64;
    if neighbour_lossless {
        assert_eq!((cb, cr), (0, 0));
        assert!(
            missing <= skips_left,
            "neighbour missing {missing} reads; kernel skips left {skips_left}"
        );
        if missed == 0 {
            assert_eq!(calm_reads, 1000);
        }
    } else {
        // Every missing read is a counted drop or a kernel skip. wl emits at
        // most 4 other events (its exec, the /proc/self/stat open, the setup
        // open, exit), which may also be among the drops.
        assert!(
            cb + cr + skips_left >= missing && cb + cr <= missing + 4,
            "missing {missing}, counted {cb}+{cr}, kernel skips left {skips_left}"
        );
    }
}

#[test]
fn flood_loss_identity_holds_and_neighbour_loses_nothing() {
    flood_identity(&[], true);
}

#[test]
fn loss_identity_holds_with_a_tiny_ring_buffer() {
    flood_identity(&["--ringbuf-bytes", "65536"], false);
}

#[test]
fn followed_nanosleep_latency_is_measured() {
    let w = PausedWl::start(&["nanosleep", "200"]).unwrap();
    let pid = w.pid().to_string();
    let dump = Dump::start(&["--follow", &pid]).unwrap();
    let m = w.release().unwrap();
    let (_, stats) = dump.stop_full().unwrap();
    let nr = action(&m, "nanosleep")["nr"].as_u64().unwrap();
    let s = sysstats_of(&stats, wl_key(&m).tgid)
        .into_iter()
        .find(|s| s["nr"].as_u64() == Some(nr))
        .expect("no nanosleep stats");
    assert_eq!(s["lat_count"].as_u64().unwrap(), 200, "{s}");
    let mean_ms = s["lat_total_ns"].as_f64().unwrap() / 200.0 / 1e6;
    assert!((1.0..=3.0).contains(&mean_ms), "mean {mean_ms} ms");
}

/// An exec right after the process used up its event budget still arrives:
/// exec carries the process's identity (exe, trust, R002/R003), so a burst
/// of opens must not be able to hide it (review finding F1).
#[test]
fn exec_after_an_exhausted_budget_is_not_lost() {
    let dump = Dump::start(&[]).unwrap();
    let m = wl(&["flood", "20000", "exec-self"]).unwrap();
    let (ev, stats) = dump.stop_full().unwrap();
    let key = wl_key(&m);
    let (budget, _) = drops_of(&stats, key.tgid);
    assert!(budget > 0, "the flood should have exhausted the budget");
    let want = action(&m, "exec-self")["exe"].as_str().unwrap().to_string();
    let execs: Vec<String> = ev
        .iter()
        .filter(|e| e.proc == key)
        .filter_map(|e| match &e.kind {
            EventKind::Exec { exe, .. } => Some(exe.escaped()),
            _ => None,
        })
        .collect();
    assert!(execs.contains(&want), "execs of {key:?}: {execs:?}");
    // Its exit right after is not lost either (review 2 finding 13).
    assert!(
        ev.iter()
            .any(|e| e.proc == key && matches!(e.kind, EventKind::Exit {})),
        "no EXIT for {key:?}"
    );
}
